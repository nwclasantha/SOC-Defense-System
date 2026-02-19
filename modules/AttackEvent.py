from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any

from modules.AttackType import AttackType
from modules.Severity import Severity

@dataclass
class AttackEvent:
    """Represents a single attack event with agent information."""
    timestamp: datetime
    ip_address: str
    rule_level: int
    rule_id: str
    description: str
    attack_type: AttackType
    payload: str
    agent_name: str
    agent_ip: str
    agent_id: str
    cve_list: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    geo_location: Optional[Dict[str, Any]] = None
    threat_intel: Optional[Dict[str, Any]] = None
    mitre_attack: Optional[Dict[str, Any]] = None  # MITRE ATT&CK mapping

    @property
    def severity(self) -> int:
        """Get severity level from rule_level"""
        return self.rule_level

    def __hash__(self):
        """Make AttackEvent hashable for deduplication."""
        return hash((self.ip_address, self.rule_id, self.timestamp, self.agent_id))
