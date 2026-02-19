import re
from dataclasses import dataclass
from typing import List

from modules.AttackType import AttackType

@dataclass
class AttackPattern:
    """Definition of an attack pattern for detection."""
    name: str
    type: AttackType
    patterns: List[str]
    confidence_weight: float = 1.0

    def matches(self, text: str) -> bool:
        """Check if any pattern matches the given text."""
        for pattern in self.patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
