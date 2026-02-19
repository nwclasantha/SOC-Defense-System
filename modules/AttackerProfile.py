from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Set, Optional, Any

from modules.AttackEvent import AttackEvent
from modules.AttackType import AttackType

@dataclass
class AttackerProfile:
    """Aggregated profile of an attacker."""
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    attack_count: int
    attack_events: List[AttackEvent]
    attack_types: Set[AttackType]
    targeted_agents: Set[str]
    cve_exploits: Set[str]
    confidence_score: float
    targeted_agents_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    geo_location: Optional[Dict[str, Any]] = None
    threat_reputation: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None  # Alias for ML detector compatibility
    risk_score: float = 0.0
    ip_validation: Optional[Dict[str, Any]] = None  # IP validation results
    ml_prediction: Optional[Dict[str, Any]] = None  # ML anomaly detection results
    advanced_ml_prediction: Optional[Dict[str, Any]] = None  # VAE + Deep SVDD results

    def calculate_risk_score(self):
        """Calculate risk score based on various factors including threat intelligence."""
        # Base behavioral score
        base_score = min(40, self.attack_count * 5)  # Cap at 40 for attack count
        diversity_bonus = min(15, len(self.attack_types) * 3)  # Cap at 15
        cve_bonus = min(20, len(self.cve_exploits) * 10)  # Cap at 20
        time_span = (self.last_seen - self.first_seen).total_seconds() / 3600
        persistence_bonus = min(10, time_span * 0.5)  # Cap at 10
        target_bonus = min(10, len(self.targeted_agents) * 2)  # Cap at 10

        behavioral_score = base_score + diversity_bonus + cve_bonus + persistence_bonus + target_bonus

        # Threat Intelligence bonus (up to 30 points)
        # USING TI VALIDATION RULES:
        # Rule 1: is_whitelisted=0 AND abuse_confidence_score>0 AND total_reports>0 → BAD IP
        # Rule 2: is_whitelisted=1 AND SANS count>0 AND attacks>0 → BAD IP
        ti_bonus = 0
        ti_data = self.threat_reputation or self.threat_intel or {}

        # Extract AbuseIPDB data
        abuse_data = ti_data.get('abuseipdb_data') or {}
        is_whitelisted = abuse_data.get('is_whitelisted', False)
        abuse_confidence = abuse_data.get('abuse_confidence_score', 0) or 0
        total_reports = abuse_data.get('total_reports', 0) or 0

        # Extract SANS ISC data
        sans_data = ti_data.get('sans_isc_data') or {}
        sans_count = sans_data.get('count', 0) or sans_data.get('attack_count', 0) or 0
        sans_attacks = sans_data.get('attacks', 0) or 0

        # Extract VirusTotal data
        vt_data = ti_data.get('virustotal_data') or {}
        vt_malicious = vt_data.get('malicious_count', 0) or vt_data.get('malicious', 0) or 0

        # TI VALIDATION RULE 1: AbuseIPDB confirms BAD
        # is_whitelisted=0 AND abuse_confidence_score>0 AND total_reports>0
        if not is_whitelisted and abuse_confidence > 0 and total_reports > 0:
            ti_bonus += 20  # Strong TI confirmation

        # TI VALIDATION RULE 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious
        # is_whitelisted=1 AND SANS count>0 AND SANS attacks>0
        elif is_whitelisted and sans_count > 0 and sans_attacks > 0:
            ti_bonus += 20  # SANS overrides whitelist

        # VirusTotal additional evidence (bonus on top of TI rules)
        if vt_malicious >= 3:
            ti_bonus += 7
        elif vt_malicious >= 1:
            ti_bonus += 3

        # Known malicious flag from enrichment
        if ti_data.get('is_malicious', False):
            ti_bonus += 5

        ti_bonus = min(30, ti_bonus)  # Cap TI bonus at 30

        # Severity bonus from attack events (up to 25 points)
        severity_bonus = 0
        max_severity = 0
        for event in self.attack_events:
            if hasattr(event, 'rule_level'):
                max_severity = max(max_severity, event.rule_level)

        if max_severity >= 15:
            severity_bonus = 25
        elif max_severity >= 12:
            severity_bonus = 20
        elif max_severity >= 10:
            severity_bonus = 15
        elif max_severity >= 7:
            severity_bonus = 10
        elif max_severity >= 5:
            severity_bonus = 5

        # Final score: behavioral (max 95) + TI (max 30) + severity (max 25) = max 150, capped at 100
        self.risk_score = min(100, behavioral_score + ti_bonus + severity_bonus)
        return self.risk_score

    def is_confirmed_malicious_public_ip(self) -> bool:
        """
        Determine if a PUBLIC IP is definitively malicious based on TI data.
        This avoids false positives from ML by using concrete TI evidence.

        Logic:
        - Condition 1: AbuseIPDB says BAD (not whitelisted + confidence > 0 + reports > 0)
        - Condition 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious (count > 0 + attacks > 0)

        Returns:
            True if IP is confirmed malicious by TI sources, False otherwise
        """
        ti_data = self.threat_reputation or self.threat_intel or {}

        # Extract AbuseIPDB data
        abuse_data = ti_data.get('abuseipdb_data') or {}
        is_whitelisted = abuse_data.get('is_whitelisted', False)
        abuse_confidence = abuse_data.get('abuse_confidence_score', 0) or 0
        total_reports = abuse_data.get('total_reports', 0) or 0

        # Extract SANS ISC data
        sans_data = ti_data.get('sans_isc_data') or {}
        sans_count = sans_data.get('count', 0) or sans_data.get('attack_count', 0) or 0
        sans_attacks = sans_data.get('attacks', 0) or 0

        # Condition 1: AbuseIPDB confirms BAD
        # is_whitelisted = 0 AND abuse_confidence_score > 0 AND total_reports > 0
        if not is_whitelisted and abuse_confidence > 0 and total_reports > 0:
            return True

        # Condition 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious
        # is_whitelisted = 1 AND SANS count > 0 AND SANS attacks > 0
        if is_whitelisted and sans_count > 0 and sans_attacks > 0:
            return True

        return False

    def get_ti_validation_reason(self) -> str:
        """
        Get the reason why IP was marked as malicious/benign by TI validation.

        Returns:
            Human-readable explanation of TI validation result
        """
        ti_data = self.threat_reputation or self.threat_intel or {}

        abuse_data = ti_data.get('abuseipdb_data') or {}
        is_whitelisted = abuse_data.get('is_whitelisted', False)
        abuse_confidence = abuse_data.get('abuse_confidence_score', 0) or 0
        total_reports = abuse_data.get('total_reports', 0) or 0

        sans_data = ti_data.get('sans_isc_data') or {}
        sans_count = sans_data.get('count', 0) or sans_data.get('attack_count', 0) or 0
        sans_attacks = sans_data.get('attacks', 0) or 0

        # Check Condition 1
        if not is_whitelisted and abuse_confidence > 0 and total_reports > 0:
            return f"AbuseIPDB: confidence={abuse_confidence}%, reports={total_reports}, not_whitelisted"

        # Check Condition 2
        if is_whitelisted and sans_count > 0 and sans_attacks > 0:
            return f"SANS ISC: count={sans_count}, attacks={sans_attacks} (whitelisted by AbuseIPDB but SANS confirms)"

        # Not confirmed malicious
        if is_whitelisted:
            return "Whitelisted by AbuseIPDB, no SANS confirmation"
        elif abuse_confidence == 0 and total_reports == 0:
            return "No AbuseIPDB reports, insufficient TI evidence"
        else:
            return "Insufficient TI evidence for confirmation"
