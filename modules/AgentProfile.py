from dataclasses import dataclass
from datetime import datetime
from typing import List, Set

from modules.AttackType import AttackType
from modules.AttackEvent import AttackEvent

@dataclass
class AgentProfile:
    """Profile of an agent under attack."""
    agent_id: str
    agent_name: str
    agent_ip: str
    total_attacks: int
    unique_attackers: Set[str]
    attack_types: Set[AttackType]
    cve_exploits: Set[str]
    first_attack: datetime
    last_attack: datetime
    attack_events: List[AttackEvent]
    risk_level: str = "Unknown"

    def calculate_risk_level(self):
        """Calculate risk level for this agent."""
        if self.total_attacks > 1000:
            self.risk_level = "CRITICAL"
        elif self.total_attacks > 100:
            self.risk_level = "HIGH"
        elif self.total_attacks > 10:
            self.risk_level = "MEDIUM"
        else:
            self.risk_level = "LOW"
        return self.risk_level
