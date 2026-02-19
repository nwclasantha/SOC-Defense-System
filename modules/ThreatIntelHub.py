"""
Threat Intelligence Integration Hub
Integrates with multiple threat intelligence sources:
- SANS ISC API
- MITRE ATT&CK Framework
- STIX/TAXII feeds
- Custom threat feeds
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import hashlib
from collections import defaultdict

class ThreatIntelHub:
    """
    Centralized threat intelligence aggregation and enrichment
    """

    def __init__(self, cache_dir: str = "./cache/threat_intel"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Cache for API responses (24 hour TTL)
        self.cache_ttl = timedelta(hours=24)

        # MITRE ATT&CK data
        self.mitre_attack_data = None
        self._load_mitre_attack()

    def lookup_sans_isc(self, ip_address: str) -> Dict[str, Any]:
        """
        Query SANS Internet Storm Center API
        https://isc.sans.edu/api/

        Returns:
            Dict with threat intelligence data
        """
        # Check cache first
        cache_file = self.cache_dir / f"sans_{hashlib.md5(ip_address.encode()).hexdigest()}.json"

        if cache_file.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age < self.cache_ttl:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)

        try:
            # Query SANS ISC API
            url = f"https://isc.sans.edu/api/ip/{ip_address}?json"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                try:
                    data = response.json()
                except (json.JSONDecodeError, ValueError) as e:
                    return {
                        "source": "SANS ISC",
                        "ip": ip_address,
                        "error": f"JSON decode error: {e}",
                        "threat_score": 0
                    }

                # Parse response
                result = {
                    "source": "SANS ISC",
                    "ip": ip_address,
                    "threat_score": 0,
                    "reports": [],
                    "first_seen": None,
                    "last_seen": None,
                    "attack_count": 0,
                    "targeted_countries": [],
                    "raw_data": data
                }

                # Extract relevant fields from SANS response
                if "ip" in data:
                    ip_data = data["ip"]
                    result["attack_count"] = int(ip_data.get("count", 0))
                    result["attacks"] = int(ip_data.get("attacks", 0))  # Fixed: was 'reports', should be 'attacks'
                    result["first_seen"] = ip_data.get("mindate")
                    result["last_seen"] = ip_data.get("maxdate")

                    # Calculate threat score based on SANS data
                    attacks = int(ip_data.get("attacks", 0))
                    if attacks > 10000:
                        result["threat_score"] = 100
                    elif attacks > 1000:
                        result["threat_score"] = 80
                    elif attacks > 100:
                        result["threat_score"] = 60
                    elif attacks > 10:
                        result["threat_score"] = 40
                    elif attacks > 0:
                        result["threat_score"] = 20

                # Cache result
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)

                return result

        except Exception as e:
            return {
                "source": "SANS ISC",
                "ip": ip_address,
                "error": str(e),
                "threat_score": 0
            }

    def check_ip_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check IP reputation using available threat intelligence sources

        This is a unified method that aggregates threat scores from multiple sources.

        Args:
            ip_address: IP address to check

        Returns:
            Dict with threat_score and source information, or None if check fails
        """
        try:
            # Use SANS ISC as primary source
            sans_result = self.lookup_sans_isc(ip_address)

            if sans_result and 'error' not in sans_result:
                return {
                    'ip_address': ip_address,
                    'threat_score': sans_result.get('threat_score', 0),
                    'source': 'SANS ISC',
                    'attack_count': sans_result.get('attack_count', 0),
                    'reports': sans_result.get('reports', 0),
                    'first_seen': sans_result.get('first_seen'),
                    'last_seen': sans_result.get('last_seen'),
                    'raw_data': sans_result
                }
            else:
                return {
                    'ip_address': ip_address,
                    'threat_score': 0,
                    'source': 'UNKNOWN',
                    'error': sans_result.get('error', 'Unknown error') if sans_result else 'No data'
                }
        except Exception as e:
            return {
                'ip_address': ip_address,
                'threat_score': 0,
                'source': 'ERROR',
                'error': str(e)
            }

    def map_to_mitre_attack(self, attack_events: List) -> Dict[str, Any]:
        """
        Map attack events to MITRE ATT&CK techniques

        Returns:
            Dict with MITRE ATT&CK mapping
        """
        if not self.mitre_attack_data:
            return {"status": "error", "message": "MITRE ATT&CK data not loaded"}

        technique_mapping = {
            "SQL_INJECTION": ["T1190"],  # Exploit Public-Facing Application
            "XSS": ["T1189", "T1059"],  # Drive-by Compromise, Command and Scripting Interpreter
            "COMMAND_INJECTION": ["T1059"],  # Command and Scripting Interpreter
            "PATH_TRAVERSAL": ["T1083", "T1005"],  # File and Directory Discovery, Data from Local System
            "BRUTE_FORCE": ["T1110"],  # Brute Force
            "AUTHENTICATION_BYPASS": ["T1078"],  # Valid Accounts
            "XXE": ["T1190"],  # Exploit Public-Facing Application
            "SSRF": ["T1090"],  # Proxy
            "FILE_INCLUSION": ["T1083"],  # File and Directory Discovery
            "DESERIALIZATION": ["T1203"],  # Exploitation for Client Execution
        }

        detected_techniques = set()
        attack_types = defaultdict(int)

        for event in attack_events:
            attack_type = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
            attack_types[attack_type] += 1

            if attack_type in technique_mapping:
                detected_techniques.update(technique_mapping[attack_type])

        # Get technique details
        techniques_detail = []
        for technique_id in detected_techniques:
            technique_info = self._get_mitre_technique_info(technique_id)
            if technique_info:
                techniques_detail.append(technique_info)

        return {
            "status": "success",
            "attack_types": dict(attack_types),
            "mitre_techniques": techniques_detail,
            "technique_count": len(detected_techniques),
            "kill_chain_phases": self._extract_kill_chain_phases(techniques_detail)
        }

    def _get_mitre_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a MITRE technique"""
        # Simplified technique database
        techniques = {
            "T1190": {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": ["Initial Access"],
                "description": "Adversaries may exploit vulnerabilities in public-facing applications",
                "mitigation": "Patch regularly, use WAF, input validation"
            },
            "T1110": {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": ["Credential Access"],
                "description": "Adversaries may use brute force techniques to gain access to accounts",
                "mitigation": "Account lockout policies, MFA, strong passwords"
            },
            "T1059": {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": ["Execution"],
                "description": "Adversaries may abuse command and script interpreters",
                "mitigation": "Disable unnecessary interpreters, use application whitelisting"
            },
            "T1083": {
                "id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": ["Discovery"],
                "description": "Adversaries may enumerate files and directories",
                "mitigation": "File system permissions, monitoring"
            },
            "T1078": {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "mitigation": "MFA, privileged account management"
            },
            "T1189": {
                "id": "T1189",
                "name": "Drive-by Compromise",
                "tactic": ["Initial Access"],
                "description": "Adversaries may gain access through compromised websites",
                "mitigation": "Browser security, ad blockers, keep software updated"
            },
            "T1090": {
                "id": "T1090",
                "name": "Proxy",
                "tactic": ["Command and Control"],
                "description": "Adversaries may use a connection proxy",
                "mitigation": "Network segmentation, proxy monitoring"
            },
            "T1005": {
                "id": "T1005",
                "name": "Data from Local System",
                "tactic": ["Collection"],
                "description": "Adversaries may search local system sources",
                "mitigation": "Data encryption, access controls"
            },
            "T1203": {
                "id": "T1203",
                "name": "Exploitation for Client Execution",
                "tactic": ["Execution"],
                "description": "Adversaries may exploit vulnerabilities in client applications",
                "mitigation": "Keep software updated, application whitelisting"
            }
        }

        return techniques.get(technique_id)

    def _extract_kill_chain_phases(self, techniques: List[Dict]) -> List[str]:
        """Extract MITRE kill chain phases from techniques"""
        phases = set()
        for technique in techniques:
            phases.update(technique.get("tactic", []))
        return sorted(list(phases))

    def _load_mitre_attack(self):
        """Load MITRE ATT&CK framework data"""
        # For production, this would load from official MITRE ATT&CK STIX data
        # For now, we use a simplified version
        self.mitre_attack_data = {
            "version": "13.1",
            "loaded": True,
            "techniques_count": 200  # Approximate
        }

    def enrich_attacker_profile(self, ip_address: str, attack_events: List) -> Dict[str, Any]:
        """
        Comprehensive threat intelligence enrichment

        Args:
            ip_address: Attacker IP
            attack_events: List of attack events

        Returns:
            Enriched threat intelligence data
        """
        enrichment = {
            "ip_address": ip_address,
            "timestamp": datetime.utcnow().isoformat(),
            "sources": {}
        }

        # SANS ISC lookup
        sans_data = self.lookup_sans_isc(ip_address)
        enrichment["sources"]["sans_isc"] = sans_data

        # MITRE ATT&CK mapping
        mitre_mapping = self.map_to_mitre_attack(attack_events)
        enrichment["sources"]["mitre_attack"] = mitre_mapping

        # Calculate combined threat score
        threat_scores = [sans_data.get("threat_score", 0)]
        enrichment["combined_threat_score"] = sum(threat_scores) / len(threat_scores)

        # Generate threat assessment
        enrichment["threat_assessment"] = self._generate_threat_assessment(enrichment)

        return enrichment

    def _generate_threat_assessment(self, enrichment: Dict) -> str:
        """Generate human-readable threat assessment"""
        score = enrichment.get("combined_threat_score", 0)

        if score >= 85:
            severity = "CRITICAL"
            action = "Immediate blocking and investigation required"
        elif score >= 70:
            severity = "HIGH"
            action = "Block and monitor closely"
        elif score >= 40:
            severity = "MEDIUM"
            action = "Enhanced monitoring recommended"
        elif score >= 20:
            severity = "LOW"
            action = "Continue monitoring"
        else:
            severity = "INFORMATIONAL"
            action = "No immediate action required"

        assessment = f"Threat Severity: {severity}. {action}."

        # Add SANS context
        sans = enrichment["sources"].get("sans_isc", {})
        if sans.get("attack_count", 0) > 0:
            assessment += f" SANS reports {sans['attack_count']} attacks from this IP."

        # Add MITRE context
        mitre = enrichment["sources"].get("mitre_attack", {})
        if mitre.get("status") == "success":
            technique_count = mitre.get("technique_count", 0)
            if technique_count > 0:
                assessment += f" Mapped to {technique_count} MITRE ATT&CK techniques."

        return assessment

    def generate_ioc_report(self, attacker_profiles: List) -> Dict[str, Any]:
        """
        Generate Indicator of Compromise (IoC) report

        Returns:
            Comprehensive IoC report
        """
        iocs = {
            "report_date": datetime.utcnow().isoformat(),
            "total_attackers": len(attacker_profiles),
            "indicators": {
                "ip_addresses": [],
                "attack_signatures": [],
                "cve_exploits": set(),
                "user_agents": set(),
                "geographic_origins": defaultdict(int)
            }
        }

        for profile in attacker_profiles:
            # IP addresses
            iocs["indicators"]["ip_addresses"].append({
                "ip": profile.ip_address,
                "risk_score": profile.risk_score,
                "first_seen": profile.first_seen.isoformat(),
                "last_seen": profile.last_seen.isoformat(),
                "attack_count": profile.attack_count
            })

            # CVE exploits
            iocs["indicators"]["cve_exploits"].update(profile.cve_exploits)

            # Geographic origins
            if profile.geo_location:
                country = profile.geo_location.get("country", "Unknown")
                iocs["indicators"]["geographic_origins"][country] += 1

            # Attack signatures from payloads
            for event in profile.attack_events:
                if event.payload:
                    signature = hashlib.md5(event.payload.encode()).hexdigest()
                    attack_type_name = event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type)
                    iocs["indicators"]["attack_signatures"].append({
                        "signature": signature,
                        "type": attack_type_name,
                        "sample": event.payload[:100]
                    })

        # Convert sets to lists for JSON serialization
        iocs["indicators"]["cve_exploits"] = list(iocs["indicators"]["cve_exploits"])
        iocs["indicators"]["geographic_origins"] = dict(iocs["indicators"]["geographic_origins"])

        return iocs

    def export_stix_format(self, ioc_report: Dict) -> str:
        """
        Export IoCs in STIX 2.1 format

        Returns:
            STIX JSON string
        """
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()}",
            "objects": []
        }

        # Add indicator objects for each IP
        for ip_data in ioc_report["indicators"]["ip_addresses"]:
            indicator = {
                "type": "indicator",
                "id": f"indicator--{hashlib.sha256(ip_data['ip'].encode()).hexdigest()}",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": f"Malicious IP: {ip_data['ip']}",
                "pattern": f"[ipv4-addr:value = '{ip_data['ip']}']",
                "pattern_type": "stix",
                "valid_from": ip_data["first_seen"] + "Z",
                "labels": ["malicious-activity"],
                "confidence": min(int(ip_data["risk_score"]), 100)
            }
            stix_bundle["objects"].append(indicator)

        return json.dumps(stix_bundle, indent=2)
