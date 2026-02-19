"""
Threat Actor Profiling Engine
Comprehensive threat actor analysis and behavioral profiling
Tracks TTP (Tactics, Techniques, and Procedures)
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json

class ThreatActorSophistication(Enum):
    """Threat actor sophistication levels"""
    SCRIPT_KIDDIE = "script_kiddie"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    APT = "apt"  # Advanced Persistent Threat

class ThreatActorMotivation(Enum):
    """Threat actor motivations"""
    FINANCIAL = "financial"
    ESPIONAGE = "espionage"
    HACKTIVISM = "hacktivism"
    DESTRUCTIVE = "destructive"
    RECONNAISSANCE = "reconnaissance"
    TESTING = "testing"

@dataclass
class ThreatActorTTP:
    """Tactics, Techniques, and Procedures"""
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    procedures: List[str] = field(default_factory=list)
    mitre_ids: List[str] = field(default_factory=list)
    tools_used: Set[str] = field(default_factory=set)
    infrastructure: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatActorProfile:
    """Comprehensive threat actor profile"""
    actor_id: str
    primary_ip: str
    aliases: List[str]
    first_seen: datetime
    last_seen: datetime
    sophistication: ThreatActorSophistication
    motivation: ThreatActorMotivation
    confidence_score: float

    # Behavioral characteristics
    ttp: ThreatActorTTP
    attack_patterns: List[str]
    targeted_sectors: Set[str]
    targeted_countries: Set[str]

    # Activity metrics
    total_attacks: int
    successful_attacks: int
    failed_attacks: int
    attack_frequency: float  # attacks per day
    preferred_attack_times: List[int]  # hours of day

    # Technical indicators
    source_ips: Set[str]
    source_asns: Set[str]
    user_agents: Set[str]
    attack_signatures: List[str]

    # Intelligence
    known_campaigns: List[str]
    related_actors: List[str]
    threat_intel_sources: List[str]

    # Risk assessment
    risk_score: float
    threat_level: str
    attribution_confidence: float

    # Metadata
    tags: Set[str]
    notes: List[str]
    last_updated: datetime

class ThreatActorProfiler:
    """
    Advanced threat actor profiling and behavioral analysis
    Tracks and profiles attackers across campaigns
    """

    def __init__(self):
        self.profiles: Dict[str, ThreatActorProfile] = {}
        self.ip_to_actor: Dict[str, str] = {}
        self.event_history: List[Dict] = []

        # Behavioral patterns
        self.attack_patterns = self._init_attack_patterns()

        # MITRE ATT&CK mapping
        self.mitre_tactics = self._init_mitre_tactics()

    def process_attack_event(self, event: Dict[str, Any]) -> Optional[ThreatActorProfile]:
        """
        Process attack event and update/create threat actor profile

        Args:
            event: Attack event dictionary

        Returns:
            Updated or created threat actor profile
        """
        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        # Store event
        self.event_history.append({
            **event,
            "processed_at": datetime.utcnow()
        })

        # Get or create actor profile
        actor_id = self._get_or_create_actor_id(source_ip)

        if actor_id in self.profiles:
            profile = self._update_profile(actor_id, event)
        else:
            profile = self._create_profile(source_ip, event)
            self.profiles[actor_id] = profile

        # Update IP mapping
        self.ip_to_actor[source_ip] = actor_id

        return profile

    def get_profile_by_ip(self, ip_address: str) -> Optional[ThreatActorProfile]:
        """Get threat actor profile by IP address"""
        actor_id = self.ip_to_actor.get(ip_address)
        if actor_id:
            return self.profiles.get(actor_id)
        return None

    def get_all_profiles(self, min_risk_score: float = 0.0) -> List[ThreatActorProfile]:
        """Get all threat actor profiles above risk threshold"""
        return [
            profile for profile in self.profiles.values()
            if profile.risk_score >= min_risk_score
        ]

    def identify_apt_actors(self) -> List[ThreatActorProfile]:
        """Identify potential APT (Advanced Persistent Threat) actors"""
        apt_profiles = []

        for profile in self.profiles.values():
            # APT characteristics
            try:
                # Handle timezone-aware and naive datetimes
                now = datetime.utcnow()
                first_seen = profile.first_seen
                # Make both timezone-naive for comparison
                if hasattr(first_seen, 'tzinfo') and first_seen.tzinfo is not None:
                    first_seen = first_seen.replace(tzinfo=None)
                is_persistent = (now - first_seen).days > 7
            except (TypeError, AttributeError):
                is_persistent = False
            is_sophisticated = profile.sophistication in [
                ThreatActorSophistication.ADVANCED,
                ThreatActorSophistication.EXPERT,
                ThreatActorSophistication.APT
            ]
            has_campaigns = len(profile.known_campaigns) > 0
            high_success_rate = (profile.successful_attacks / max(profile.total_attacks, 1)) > 0.3

            if is_persistent and is_sophisticated and (has_campaigns or high_success_rate):
                profile.sophistication = ThreatActorSophistication.APT
                apt_profiles.append(profile)

        return apt_profiles

    def cluster_related_actors(self) -> List[List[str]]:
        """
        Cluster related threat actors based on behavioral similarity

        Returns:
            List of actor ID clusters
        """
        clusters = []
        processed = set()

        for actor_id, profile in self.profiles.items():
            if actor_id in processed:
                continue

            cluster = [actor_id]
            processed.add(actor_id)

            # Find similar actors
            for other_id, other_profile in self.profiles.items():
                if other_id in processed:
                    continue

                similarity = self._calculate_similarity(profile, other_profile)

                if similarity > 0.7:  # High similarity threshold
                    cluster.append(other_id)
                    processed.add(other_id)

            if len(cluster) > 1:
                clusters.append(cluster)

        return clusters

    def generate_threat_report(self, actor_id: str) -> Dict[str, Any]:
        """
        Generate comprehensive threat report for actor

        Args:
            actor_id: Threat actor ID

        Returns:
            Detailed threat report
        """
        profile = self.profiles.get(actor_id)
        if not profile:
            return {"error": "Actor not found"}

        # Calculate additional metrics
        success_rate = (profile.successful_attacks / max(profile.total_attacks, 1)) * 100
        days_active = (profile.last_seen - profile.first_seen).days + 1
        avg_attacks_per_day = profile.total_attacks / max(days_active, 1)

        return {
            "actor_id": actor_id,
            "summary": {
                "primary_ip": profile.primary_ip,
                "sophistication": profile.sophistication.value,
                "motivation": profile.motivation.value,
                "threat_level": profile.threat_level,
                "risk_score": profile.risk_score,
                "confidence": profile.attribution_confidence
            },
            "activity": {
                "first_seen": profile.first_seen.isoformat(),
                "last_seen": profile.last_seen.isoformat(),
                "days_active": days_active,
                "total_attacks": profile.total_attacks,
                "successful_attacks": profile.successful_attacks,
                "success_rate_percent": success_rate,
                "avg_attacks_per_day": avg_attacks_per_day,
                "preferred_attack_hours": profile.preferred_attack_times
            },
            "ttp": {
                "tactics": profile.ttp.tactics,
                "techniques": profile.ttp.techniques,
                "mitre_att&ck": profile.ttp.mitre_ids,
                "tools": list(profile.ttp.tools_used),
                "attack_patterns": profile.attack_patterns
            },
            "targeting": {
                "sectors": list(profile.targeted_sectors),
                "countries": list(profile.targeted_countries)
            },
            "infrastructure": {
                "source_ips": list(profile.source_ips),
                "asns": list(profile.source_asns),
                "user_agents": list(profile.user_agents)
            },
            "intelligence": {
                "known_campaigns": profile.known_campaigns,
                "related_actors": profile.related_actors,
                "sources": profile.threat_intel_sources
            },
            "recommendations": self._generate_recommendations(profile)
        }

    def export_iocs(self, actor_id: str) -> Dict[str, List[str]]:
        """
        Export Indicators of Compromise for threat actor

        Args:
            actor_id: Threat actor ID

        Returns:
            Dictionary of IOC types and values
        """
        profile = self.profiles.get(actor_id)
        if not profile:
            return {}

        return {
            "ip_addresses": list(profile.source_ips),
            "asns": list(profile.source_asns),
            "user_agents": list(profile.user_agents),
            "attack_signatures": profile.attack_signatures,
            "tools": list(profile.ttp.tools_used),
            "campaigns": profile.known_campaigns
        }

    def _create_profile(self, ip_address: str, event: Dict) -> ThreatActorProfile:
        """Create new threat actor profile"""
        actor_id = self._generate_actor_id(ip_address)

        attack_type = event.get("attack_type", "unknown")

        profile = ThreatActorProfile(
            actor_id=actor_id,
            primary_ip=ip_address,
            aliases=[],
            first_seen=event.get("timestamp", datetime.utcnow()),
            last_seen=event.get("timestamp", datetime.utcnow()),
            sophistication=self._assess_sophistication(event),
            motivation=self._assess_motivation(event),
            confidence_score=0.5,
            ttp=ThreatActorTTP(),
            attack_patterns=[attack_type],
            targeted_sectors=set(),
            targeted_countries=set(),
            total_attacks=1,
            successful_attacks=1 if event.get("successful") else 0,
            failed_attacks=0 if event.get("successful") else 1,
            attack_frequency=0.0,
            preferred_attack_times=[event.get("timestamp", datetime.utcnow()).hour],
            source_ips={ip_address},
            source_asns=set(),
            user_agents=set(),
            attack_signatures=[],
            known_campaigns=[],
            related_actors=[],
            threat_intel_sources=[],
            risk_score=self._calculate_risk_score(event),
            threat_level=self._determine_threat_level(event),
            attribution_confidence=0.3,
            tags=set(),
            notes=[],
            last_updated=datetime.utcnow()
        )

        # Extract TTP
        self._extract_ttp(profile, event)

        return profile

    def _update_profile(self, actor_id: str, event: Dict) -> ThreatActorProfile:
        """Update existing threat actor profile"""
        profile = self.profiles[actor_id]

        # Update timestamps
        profile.last_seen = event.get("timestamp", datetime.utcnow())
        profile.last_updated = datetime.utcnow()

        # Update attack counts
        profile.total_attacks += 1
        if event.get("successful"):
            profile.successful_attacks += 1
        else:
            profile.failed_attacks += 1

        # Update attack patterns
        attack_type = event.get("attack_type")
        if attack_type and attack_type not in profile.attack_patterns:
            profile.attack_patterns.append(attack_type)

        # Update IPs
        source_ip = event.get("source_ip")
        if source_ip:
            profile.source_ips.add(source_ip)

        # Update user agents
        user_agent = event.get("user_agent")
        if user_agent:
            profile.user_agents.add(user_agent)

        # Update preferred attack times
        hour = event.get("timestamp", datetime.utcnow()).hour
        if hour not in profile.preferred_attack_times:
            profile.preferred_attack_times.append(hour)

        # Update TTP
        self._extract_ttp(profile, event)

        # Recalculate metrics
        days_active = (profile.last_seen - profile.first_seen).days + 1
        profile.attack_frequency = profile.total_attacks / max(days_active, 1)

        # Update sophistication and risk
        profile.sophistication = self._assess_sophistication_from_profile(profile)
        profile.risk_score = self._calculate_profile_risk_score(profile)
        profile.threat_level = self._determine_threat_level_from_profile(profile)

        return profile

    def _extract_ttp(self, profile: ThreatActorProfile, event: Dict):
        """Extract Tactics, Techniques, and Procedures from event"""
        attack_type = event.get("attack_type", "").lower()

        # Map to MITRE ATT&CK
        if "brute_force" in attack_type or "password" in attack_type:
            profile.ttp.techniques.append("Brute Force")
            profile.ttp.mitre_ids.append("T1110")
            profile.ttp.tactics.append("Credential Access")

        if "sql" in attack_type or "injection" in attack_type:
            profile.ttp.techniques.append("Exploit Public-Facing Application")
            profile.ttp.mitre_ids.append("T1190")
            profile.ttp.tactics.append("Initial Access")

        if "scan" in attack_type or "reconnaissance" in attack_type:
            profile.ttp.techniques.append("Active Scanning")
            profile.ttp.mitre_ids.append("T1595")
            profile.ttp.tactics.append("Reconnaissance")

        if "xss" in attack_type or "csrf" in attack_type:
            profile.ttp.techniques.append("Drive-by Compromise")
            profile.ttp.mitre_ids.append("T1189")
            profile.ttp.tactics.append("Initial Access")

        if "ddos" in attack_type or "dos" in attack_type:
            profile.ttp.techniques.append("Network Denial of Service")
            profile.ttp.mitre_ids.append("T1498")
            profile.ttp.tactics.append("Impact")

        if "privilege" in attack_type or "escalation" in attack_type:
            profile.ttp.techniques.append("Exploitation for Privilege Escalation")
            profile.ttp.mitre_ids.append("T1068")
            profile.ttp.tactics.append("Privilege Escalation")

        # Extract tools
        tool = event.get("tool")
        if tool:
            profile.ttp.tools_used.add(tool)

        # Deduplicate
        profile.ttp.tactics = list(set(profile.ttp.tactics))
        profile.ttp.techniques = list(set(profile.ttp.techniques))
        profile.ttp.mitre_ids = list(set(profile.ttp.mitre_ids))

    def _assess_sophistication(self, event: Dict) -> ThreatActorSophistication:
        """Assess sophistication from single event"""
        attack_type = event.get("attack_type", "").lower()

        if "apt" in attack_type or "zero_day" in attack_type:
            return ThreatActorSophistication.APT
        elif "advanced" in attack_type or "custom" in attack_type:
            return ThreatActorSophistication.ADVANCED
        elif "automated" in attack_type or "tool" in attack_type:
            return ThreatActorSophistication.INTERMEDIATE
        else:
            return ThreatActorSophistication.SCRIPT_KIDDIE

    def _assess_sophistication_from_profile(self, profile: ThreatActorProfile) -> ThreatActorSophistication:
        """Assess sophistication from complete profile"""
        # Multiple indicators
        unique_techniques = len(set(profile.ttp.techniques))
        unique_ips = len(profile.source_ips)
        success_rate = profile.successful_attacks / max(profile.total_attacks, 1)
        days_active = (profile.last_seen - profile.first_seen).days

        score = 0

        if unique_techniques > 5:
            score += 2
        if unique_ips > 3:
            score += 1
        if success_rate > 0.5:
            score += 2
        if days_active > 30:
            score += 1
        if len(profile.ttp.tools_used) > 2:
            score += 1

        if score >= 6:
            return ThreatActorSophistication.APT
        elif score >= 4:
            return ThreatActorSophistication.ADVANCED
        elif score >= 2:
            return ThreatActorSophistication.INTERMEDIATE
        else:
            return ThreatActorSophistication.SCRIPT_KIDDIE

    def _assess_motivation(self, event: Dict) -> ThreatActorMotivation:
        """Assess likely motivation from event"""
        attack_type = event.get("attack_type", "").lower()

        if "ransom" in attack_type or "crypto" in attack_type:
            return ThreatActorMotivation.FINANCIAL
        elif "espionage" in attack_type or "exfiltration" in attack_type:
            return ThreatActorMotivation.ESPIONAGE
        elif "defacement" in attack_type or "political" in attack_type:
            return ThreatActorMotivation.HACKTIVISM
        elif "wipe" in attack_type or "destroy" in attack_type:
            return ThreatActorMotivation.DESTRUCTIVE
        elif "scan" in attack_type or "probe" in attack_type:
            return ThreatActorMotivation.RECONNAISSANCE
        else:
            return ThreatActorMotivation.TESTING

    def _calculate_risk_score(self, event: Dict) -> float:
        """Calculate risk score from event (0-1)"""
        severity = event.get("severity", 5)
        return min(severity / 10.0, 1.0)

    def _calculate_profile_risk_score(self, profile: ThreatActorProfile) -> float:
        """Calculate comprehensive risk score from profile"""
        score = 0.0

        # Sophistication
        soph_scores = {
            ThreatActorSophistication.SCRIPT_KIDDIE: 0.2,
            ThreatActorSophistication.INTERMEDIATE: 0.4,
            ThreatActorSophistication.ADVANCED: 0.7,
            ThreatActorSophistication.EXPERT: 0.85,
            ThreatActorSophistication.APT: 1.0
        }
        score += soph_scores.get(profile.sophistication, 0.5) * 0.3

        # Success rate
        success_rate = profile.successful_attacks / max(profile.total_attacks, 1)
        score += success_rate * 0.3

        # Attack frequency
        if profile.attack_frequency > 10:
            score += 0.2
        elif profile.attack_frequency > 5:
            score += 0.1

        # Persistence
        days_active = (profile.last_seen - profile.first_seen).days
        if days_active > 30:
            score += 0.2
        elif days_active > 7:
            score += 0.1

        return min(score, 1.0)

    def _determine_threat_level(self, event: Dict) -> str:
        """Determine threat level from event"""
        severity = event.get("severity", 5)

        if severity >= 9:
            return "CRITICAL"
        elif severity >= 7:
            return "HIGH"
        elif severity >= 5:
            return "MEDIUM"
        else:
            return "LOW"

    def _determine_threat_level_from_profile(self, profile: ThreatActorProfile) -> str:
        """Determine threat level from profile"""
        if profile.risk_score >= 0.8:
            return "CRITICAL"
        elif profile.risk_score >= 0.6:
            return "HIGH"
        elif profile.risk_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"

    def _calculate_similarity(self, profile1: ThreatActorProfile, profile2: ThreatActorProfile) -> float:
        """Calculate behavioral similarity between two actors"""
        score = 0.0

        # Attack pattern similarity
        common_patterns = set(profile1.attack_patterns) & set(profile2.attack_patterns)
        total_patterns = set(profile1.attack_patterns) | set(profile2.attack_patterns)
        if total_patterns:
            score += (len(common_patterns) / len(total_patterns)) * 0.3

        # TTP similarity
        common_techniques = set(profile1.ttp.techniques) & set(profile2.ttp.techniques)
        total_techniques = set(profile1.ttp.techniques) | set(profile2.ttp.techniques)
        if total_techniques:
            score += (len(common_techniques) / len(total_techniques)) * 0.3

        # Timing similarity
        common_hours = set(profile1.preferred_attack_times) & set(profile2.preferred_attack_times)
        if len(common_hours) >= 3:
            score += 0.2

        # Tool similarity
        common_tools = profile1.ttp.tools_used & profile2.ttp.tools_used
        total_tools = profile1.ttp.tools_used | profile2.ttp.tools_used
        if total_tools:
            score += (len(common_tools) / len(total_tools)) * 0.2

        return min(score, 1.0)

    def _generate_recommendations(self, profile: ThreatActorProfile) -> List[str]:
        """Generate security recommendations based on threat actor profile"""
        recommendations = []

        if profile.threat_level in ["CRITICAL", "HIGH"]:
            recommendations.append("Block all source IPs immediately")
            recommendations.append("Enable enhanced monitoring for similar attack patterns")

        if profile.sophistication in [ThreatActorSophistication.APT, ThreatActorSophistication.EXPERT]:
            recommendations.append("Initiate APT response protocol")
            recommendations.append("Conduct comprehensive threat hunt")

        if "Brute Force" in profile.ttp.techniques:
            recommendations.append("Enforce strong password policies and MFA")

        if "SQL Injection" in profile.attack_patterns:
            recommendations.append("Review and patch SQL injection vulnerabilities")

        if profile.attack_frequency > 5:
            recommendations.append("Implement rate limiting and IP reputation blocking")

        return recommendations

    def _generate_actor_id(self, ip_address: str) -> str:
        """Generate unique actor ID"""
        return hashlib.sha256(f"actor_{ip_address}_{datetime.utcnow()}".encode()).hexdigest()[:16]

    def _get_or_create_actor_id(self, ip_address: str) -> str:
        """Get existing actor ID or create new one"""
        if ip_address in self.ip_to_actor:
            return self.ip_to_actor[ip_address]
        return self._generate_actor_id(ip_address)

    def _init_attack_patterns(self) -> Dict[str, List[str]]:
        """Initialize attack pattern definitions"""
        return {
            "reconnaissance": ["port_scan", "network_scan", "enumeration"],
            "initial_access": ["phishing", "exploit", "brute_force"],
            "execution": ["command_injection", "code_execution"],
            "persistence": ["backdoor", "rootkit", "scheduled_task"],
            "privilege_escalation": ["exploit_elevation", "token_manipulation"],
            "defense_evasion": ["obfuscation", "anti_forensics"],
            "credential_access": ["credential_dumping", "password_cracking"],
            "discovery": ["system_enumeration", "network_discovery"],
            "lateral_movement": ["remote_services", "ssh_hijacking"],
            "collection": ["data_scraping", "keylogging"],
            "exfiltration": ["data_transfer", "c2_communication"],
            "impact": ["ransomware", "ddos", "data_destruction"]
        }

    def _init_mitre_tactics(self) -> List[str]:
        """Initialize MITRE ATT&CK tactics"""
        return [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get profiler statistics"""
        total_actors = len(self.profiles)

        sophistication_counts = Counter(p.sophistication for p in self.profiles.values())
        threat_level_counts = Counter(p.threat_level for p in self.profiles.values())

        return {
            "total_actors": total_actors,
            "by_sophistication": {k.value: v for k, v in sophistication_counts.items()},
            "by_threat_level": dict(threat_level_counts),
            "apt_actors": len(self.identify_apt_actors()),
            "events_processed": len(self.event_history)
        }
