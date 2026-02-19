from abc import ABC, abstractmethod
from typing import Tuple

from modules.AttackType import AttackType

class AttackDetector(ABC):
    """Abstract base class for attack detection strategies."""

    @abstractmethod
    def detect(self, log_data: str) -> Tuple[bool, AttackType, str]:
        """Detect if log contains an attack."""
        pass
