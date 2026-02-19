"""
Threat Intelligence Aggregator
Combines data from multiple threat intelligence sources and classifies attacks
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from modules.AttackEvent import AttackEvent
from modules.AttackType import AttackType
from modules.MitreAttackMapper import MitreAttackMapper

@dataclass
class ThreatIntelligenceReport:
    """Comprehensive threat intelligence report"""
    ip_address: str
    reputation_score: int  # 0-100 (0=clean, 100=malicious)
    threat_level: str  # low, medium, high, critical
    categories: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    threat_actor: Optional[str] = None
    malware_families: List[str] = None
    associated_domains: List[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    confidence: int = 0
    sources: List[str] = None

    def __post_init__(self):
        if self.malware_families is None:
            self.malware_families = []
        if self.associated_domains is None:
            self.associated_domains = []
        if self.sources is None:
            self.sources = []

class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple sources"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.mitre_mapper = MitreAttackMapper.get_instance()  # Singleton - loads once
        self.known_threat_actors = self._initialize_threat_actors()
        self.malware_signatures = self._initialize_malware_signatures()

        # If MITRE loader available, use real threat actors from database
        if self.mitre_mapper.mitre_loader:
            self.logger.info(f"Using local MITRE DB with {len(self.mitre_mapper.mitre_loader.groups)} threat actors")
            self._load_mitre_threat_actors()

    def _initialize_threat_actors(self) -> Dict[str, Dict]:
        """Initialize known threat actor patterns"""
        return {
            "APT28": {
                "aliases": ["Fancy Bear", "Sofacy", "Sednit"],
                "origin": "Russia",
                "tactics": ["T1190", "T1059", "T1071"],
                "targets": ["Government", "Military", "Critical Infrastructure"]
            },
            "APT29": {
                "aliases": ["Cozy Bear", "The Dukes"],
                "origin": "Russia",
                "tactics": ["T1566", "T1059.001", "T1071"],
                "targets": ["Government", "Think Tanks", "Healthcare"]
            },
            "APT41": {
                "aliases": ["Barium", "Winnti"],
                "origin": "China",
                "tactics": ["T1190", "T1505.003", "T1059"],
                "targets": ["Gaming", "Healthcare", "Telecommunications"]
            },
            "Lazarus Group": {
                "aliases": ["Hidden Cobra", "Guardians of Peace"],
                "origin": "North Korea",
                "tactics": ["T1486", "T1059", "T1071"],
                "targets": ["Financial", "Cryptocurrency", "Defense"]
            },
            "FIN7": {
                "aliases": ["Carbanak"],
                "origin": "Unknown",
                "tactics": ["T1566", "T1059", "T1555"],
                "targets": ["Retail", "Hospitality", "Financial"]
            }
        }

    def _initialize_malware_signatures(self) -> Dict[str, Dict]:
        """Initialize known malware signatures"""
        return {
            "Emotet": {
                "type": "Trojan/Botnet",
                "tactics": ["T1566", "T1059", "T1055"],
                "severity": "high",
                "indicators": ["emotet", "epoch"]
            },
            "TrickBot": {
                "type": "Banking Trojan",
                "tactics": ["T1555", "T1083", "T1071"],
                "severity": "high",
                "indicators": ["trickbot", "anchor"]
            },
            "Cobalt Strike": {
                "type": "Post-Exploitation Tool",
                "tactics": ["T1071", "T1090", "T1055"],
                "severity": "critical",
                "indicators": ["beacon", "malleable"]
            },
            "Mimikatz": {
                "type": "Credential Dumper",
                "tactics": ["T1003", "T1555", "T1558"],
                "severity": "critical",
                "indicators": ["mimikatz", "sekurlsa"]
            },
            "WannaCry": {
                "type": "Ransomware",
                "tactics": ["T1486", "T1490", "T1082"],
                "severity": "critical",
                "indicators": ["wannacry", "wcry", "wncry"]
            }
        }

    def _load_mitre_threat_actors(self):
        """Load threat actors from MITRE database"""
        loader = self.mitre_mapper.mitre_loader
        if not loader:
            return

        # Add real MITRE threat actors to our dictionary
        for group_id, group in loader.groups.items():
            # Extract description for targets (simplified)
            description = group.description.lower()
            targets = []
            if "government" in description:
                targets.append("Government")
            if "financial" in description or "bank" in description:
                targets.append("Financial")
            if "healthcare" in description or "health" in description:
                targets.append("Healthcare")
            if "critical infrastructure" in description or "infrastructure" in description:
                targets.append("Critical Infrastructure")
            if "military" in description or "defense" in description:
                targets.append("Military/Defense")

            # Get techniques used by this group
            techniques = [t for t in group.techniques if t]

            self.known_threat_actors[group.name] = {
                "aliases": group.aliases,
                "origin": "See MITRE ATT&CK",  # Could parse from description
                "tactics": techniques[:10],  # First 10 techniques
                "targets": targets if targets else ["Various"],
                "mitre_id": group_id,
                "mitre_url": group.url
            }

    def enrich_attack_event(self, event: AttackEvent) -> AttackEvent:
        """Enrich attack event with threat intelligence and MITRE mappings"""
        # Add MITRE ATT&CK mapping
        mitre_mapping = self.mitre_mapper.get_attack_summary(
            event.attack_type,
            event.description
        )
        event.mitre_attack = mitre_mapping

        # Add threat intelligence
        threat_intel = self.get_threat_intelligence(event.ip_address, event.description)
        event.threat_intel = threat_intel

        return event

    def get_threat_intelligence(self, ip_address: str,
                                description: str = "") -> Dict[str, Any]:
        """Get aggregated threat intelligence for an IP"""
        # In production, this would query multiple threat feeds
        # For now, we'll do pattern-based analysis

        categories = []
        malware_families = []
        threat_level = "low"
        reputation_score = 0
        sources = ["Internal Analysis"]

        description_lower = description.lower()

        # Check for malware indicators
        for malware_name, malware_info in self.malware_signatures.items():
            for indicator in malware_info["indicators"]:
                if indicator in description_lower:
                    malware_families.append(malware_name)
                    categories.append(malware_info["type"])
                    if malware_info["severity"] == "critical":
                        reputation_score = max(reputation_score, 90)
                        threat_level = "critical"
                    elif malware_info["severity"] == "high":
                        reputation_score = max(reputation_score, 75)
                        threat_level = "high"

        # Analyze attack patterns
        if "injection" in description_lower or "exploit" in description_lower:
            categories.append("Web Attack")
            reputation_score = max(reputation_score, 60)
            threat_level = "medium" if threat_level == "low" else threat_level

        if "brute" in description_lower or "password" in description_lower:
            categories.append("Credential Access")
            reputation_score = max(reputation_score, 55)
            threat_level = "medium" if threat_level == "low" else threat_level

        if "shell" in description_lower or "command" in description_lower:
            categories.append("Command Execution")
            reputation_score = max(reputation_score, 70)
            threat_level = "high"

        if "ransomware" in description_lower or "encrypt" in description_lower:
            categories.append("Ransomware")
            reputation_score = max(reputation_score, 95)
            threat_level = "critical"

        # Remove duplicates
        categories = list(set(categories))

        return {
            "ip_address": ip_address,
            "reputation_score": reputation_score,
            "threat_level": threat_level,
            "categories": categories if categories else ["Unknown"],
            "malware_families": malware_families,
            "confidence": 75 if categories else 30,
            "sources": sources,
            "last_seen": datetime.now().isoformat()
        }

    def classify_attacker(self, events: List[AttackEvent]) -> Dict[str, Any]:
        """Classify attacker based on multiple events"""
        if not events:
            return {}

        # Aggregate data from all events
        all_tactics = set()
        all_techniques = set()
        all_categories = set()
        all_malware = set()

        for event in events:
            if event.mitre_attack:
                for tactic in event.mitre_attack.get('mitre_tactics', []):
                    all_tactics.add(tactic['name'])
                for tech in event.mitre_attack.get('mitre_techniques', []):
                    all_techniques.add(tech['id'])

            if event.threat_intel:
                all_categories.update(event.threat_intel.get('categories', []))
                all_malware.update(event.threat_intel.get('malware_families', []))

        # Try to match to known threat actors
        potential_actors = []
        for actor_name, actor_info in self.known_threat_actors.items():
            # Check if techniques match
            actor_techniques = set(actor_info.get('tactics', []))
            if actor_techniques & all_techniques:  # If there's overlap
                match_score = len(actor_techniques & all_techniques) / len(actor_techniques) * 100
                potential_actors.append({
                    'name': actor_name,
                    'aliases': actor_info['aliases'],
                    'origin': actor_info['origin'],
                    'match_score': match_score,
                    'confidence': 'medium' if match_score > 30 else 'low'
                })

        # Sort by match score
        potential_actors.sort(key=lambda x: x['match_score'], reverse=True)

        # Determine attacker profile
        attacker_profile = {
            'skill_level': self._assess_skill_level(all_techniques),
            'tactics_used': list(all_tactics),
            'techniques_used': list(all_techniques),
            'threat_categories': list(all_categories),
            'malware_used': list(all_malware),
            'potential_threat_actors': potential_actors[:3],  # Top 3 matches
            'attack_sophistication': self._assess_sophistication(events),
            'campaign_type': self._identify_campaign_type(all_categories, all_tactics)
        }

        return attacker_profile

    def _assess_skill_level(self, techniques: set) -> str:
        """Assess attacker skill level based on techniques"""
        if not techniques:
            return "Unknown"

        technique_count = len(techniques)

        # Check for advanced techniques
        advanced_techniques = {"T1068", "T1027", "T1140", "T1055", "T1562"}
        if advanced_techniques & techniques:
            return "Advanced"

        if technique_count >= 5:
            return "Intermediate"
        elif technique_count >= 2:
            return "Novice"
        else:
            return "Script Kiddie"

    def _assess_sophistication(self, events: List[AttackEvent]) -> str:
        """Assess attack sophistication"""
        if not events:
            return "Unknown"

        # Check for multiple attack vectors
        attack_types = {event.attack_type for event in events}
        if len(attack_types) >= 3:
            return "High - Multi-vector attack"

        # Check for advanced payloads
        for event in events:
            if event.payload:
                if "obfusc" in event.payload.lower() or "encod" in event.payload.lower():
                    return "High - Obfuscated payloads"

        # Check for persistence mechanisms
        for event in events:
            if event.mitre_attack:
                for tactic in event.mitre_attack.get('mitre_tactics', []):
                    if tactic['name'] == 'PERSISTENCE':
                        return "Medium - Persistence established"

        if len(events) > 5:
            return "Medium - Sustained campaign"

        return "Low - Opportunistic attack"

    def _identify_campaign_type(self, categories: set, tactics: set) -> str:
        """Identify type of campaign"""
        if "Ransomware" in categories:
            return "Ransomware Campaign"
        if "Credential Access" in categories or "CREDENTIAL_ACCESS" in tactics:
            return "Credential Harvesting"
        if "Web Attack" in categories:
            return "Web Application Attack"
        if "EXFILTRATION" in tactics:
            return "Data Exfiltration"
        if "Command Execution" in categories:
            return "Command & Control Establishment"

        return "General Intrusion Attempt"

    def generate_threat_report(self, events: List[AttackEvent]) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        if not events:
            return {}

        # Enrich all events
        enriched_events = [self.enrich_attack_event(event) for event in events]

        # Get IP threat intelligence
        ip_addresses = list(set(event.ip_address for event in enriched_events))
        ip_threat_intel = {}
        for ip in ip_addresses:
            ip_threat_intel[ip] = self.get_threat_intelligence(ip, "")

        # Classify attacker
        attacker_classification = self.classify_attacker(enriched_events)

        # Aggregate MITRE mappings
        all_mitre_tactics = {}
        all_mitre_techniques = {}

        for event in enriched_events:
            if event.mitre_attack:
                for tactic in event.mitre_attack.get('mitre_tactics', []):
                    tactic_name = tactic['name']
                    all_mitre_tactics[tactic_name] = all_mitre_tactics.get(tactic_name, 0) + 1

                for tech in event.mitre_attack.get('mitre_techniques', []):
                    tech_id = tech['id']
                    all_mitre_techniques[tech_id] = {
                        'name': tech['name'],
                        'tactic': tech['tactic'],
                        'count': all_mitre_techniques.get(tech_id, {}).get('count', 0) + 1
                    }

        return {
            'summary': {
                'total_events': len(enriched_events),
                'unique_ips': len(ip_addresses),
                'time_range': {
                    'start': min(e.timestamp for e in enriched_events).isoformat(),
                    'end': max(e.timestamp for e in enriched_events).isoformat()
                },
                'overall_threat_level': self._calculate_overall_threat_level(enriched_events)
            },
            'attacker_classification': attacker_classification,
            'ip_threat_intelligence': ip_threat_intel,
            'mitre_attack': {
                'tactics': all_mitre_tactics,
                'techniques': all_mitre_techniques
            },
            'events': [self._event_to_dict(e) for e in enriched_events]
        }

    def _calculate_overall_threat_level(self, events: List[AttackEvent]) -> str:
        """Calculate overall threat level"""
        if not events:
            return "low"

        # Check for critical indicators
        for event in events:
            if event.threat_intel:
                if event.threat_intel.get('threat_level') == 'critical':
                    return "critical"

        # Count high severity events
        high_severity_count = sum(1 for e in events if e.rule_level >= 10)
        if high_severity_count >= 3:
            return "high"
        elif high_severity_count >= 1:
            return "medium"

        return "low"

    def _event_to_dict(self, event: AttackEvent) -> Dict:
        """Convert event to dictionary"""
        return {
            'timestamp': event.timestamp.isoformat(),
            'ip_address': event.ip_address,
            'rule_level': event.rule_level,
            'rule_id': event.rule_id,
            'description': event.description,
            'attack_type': event.attack_type.value if hasattr(event.attack_type, 'value') else str(event.attack_type),
            'payload': event.payload[:200] if event.payload else "",  # Truncate for report
            'agent_name': event.agent_name,
            'mitre_attack': event.mitre_attack,
            'threat_intel': event.threat_intel
        }
