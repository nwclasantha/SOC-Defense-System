from abc import ABC, abstractmethod
from typing import List, Dict, Any

class IPExtractor(ABC):
    """Abstract base class for IP extraction strategies."""

    @abstractmethod
    def extract(self, data: Dict[str, Any]) -> List[str]:
        """Extract IP addresses from alert data."""
        pass
