from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class CLIConfiguration:
    """System configuration for analyzer."""
    elasticsearch_url: str
    elasticsearch_user: str
    elasticsearch_password: str
    wazuh_api_url: Optional[str] = None
    wazuh_api_user: Optional[str] = None
    wazuh_api_password: Optional[str] = None
    verify_ssl: bool = False
    default_hours_back: int = 168  # 7 days (reduced from 30 days for better performance)
    min_severity_level: int = 3  # Get LOW+ (3-4), MEDIUM (5-6), HIGH (7-11), CRITICAL (12+). Ignore very low noise (0-2).
    max_results_per_query: int = 5000  # Reduced from 10000 for faster queries
    max_workers: int = 10
    batch_size: int = 1000
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0
    enable_cache: bool = True
    cache_ttl_hours: int = 24
    cache_directory: str = "./cache"
    geoip_database_path: Optional[str] = None
    output_directory: str = "./wazuh_analysis_output"
    export_formats: List[str] = field(default_factory=lambda: ["csv", "json", "txt", "agent_report"])
    # Threat Intelligence API Keys
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    # Threat Intelligence Enable Flags (can be disabled to save API quota)
    enable_virustotal: bool = False  # DISABLED by default - VT is slow (4/min). Enable in Settings if needed.
    enable_abuseipdb: bool = True    # Fast (30/min)
    enable_sans_isc: bool = True     # Fast (60/min)
