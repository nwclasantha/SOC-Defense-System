from abc import ABC, abstractmethod
from typing import List, Dict, Any

class DataSource(ABC):
    """Abstract base class for data sources."""

    @abstractmethod
    async def query_alerts(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query alerts from the data source."""
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the data source is accessible."""
        pass
