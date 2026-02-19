from enum import Enum

class Severity(Enum):
    """Wazuh alert severity levels."""
    LOW = range(0, 7)
    MEDIUM = range(7, 10)
    HIGH = range(10, 15)
    CRITICAL = range(15, 21)

    @classmethod
    def from_level(cls, level: int):
        """Get severity enum from numeric level."""
        for severity in cls:
            if level in severity.value:
                return severity
        return cls.LOW
