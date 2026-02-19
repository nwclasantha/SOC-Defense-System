import re
import logging
import ipaddress
from typing import List, Dict, Any
from functools import lru_cache

# Module imports
from modules.IPExtractor import IPExtractor

class SmartIPExtractor(IPExtractor):
    """Intelligent IP extraction with validation and filtering."""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

        # Common fields where IPs are found (attacker or monitored systems)
        self.ip_fields = [
            # Standard attack fields
            'data.srcip',
            'data.src_ip',
            'data.source_ip',
            'syslog.srcip',

            # Cloud providers
            'data.aws.srcaddr',
            'data.gcp.jsonPayload.sourceIP',
            'data.azure.properties.clientIP',

            # Network
            'data.netflow.sourceIPv4Address',

            # Windows event data
            'data.win.eventdata.ipAddress',
            'data.win.eventdata.IpAddress',
            'data.win.eventdata.SourceAddress',
            'data.win.eventdata.ClientAddress',

            # Agent IP (monitored system)
            'agent.ip',

            # Destination IPs (might be useful)
            'data.dstip',
            'data.dst_ip',
            'data.destination_ip',

            # Web logs
            'data.srcip',
            'data.client_ip'
        ]

    def extract(self, data: Dict[str, Any]) -> List[str]:
        """Extract and validate IP addresses from alert data."""
        extracted_ips = set()

        # Get _source if present (Elasticsearch document structure)
        source = data.get('_source', data)

        # Extract from structured fields (look inside _source)
        for field_path in self.ip_fields:
            value = self._get_nested_value(source, field_path)
            if value:
                extracted_ips.add(str(value))

        # Extract from full log
        full_log = source.get('full_log', '')
        if full_log:
            # Find all IPs in the log
            found_ips = self.ip_pattern.findall(full_log)

            # For web logs, prioritize IPs at the beginning (usually the client IP)
            if any(keyword in full_log.lower() for keyword in ['http', 'get', 'post', 'put', 'delete']):
                # Web log pattern: CLIENT_IP - - [timestamp] "METHOD /path HTTP/1.1" ...
                web_log_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', full_log)
                if web_log_match:
                    extracted_ips.add(web_log_match.group(1))

            # Add all found IPs
            extracted_ips.update(found_ips)

        # Filter and validate IPs (MODIFIED: Accept both public AND private IPs)
        valid_ips = []
        for ip_str in extracted_ips:
            if self._is_valid_ip(ip_str):
                valid_ips.append(ip_str)

        return list(set(valid_ips))

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        value = data

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None

        return value

    @lru_cache(maxsize=10000)
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if IP is valid (both public and private accepted)."""
        try:
            ip = ipaddress.ip_address(ip_str)

            # Check if it's IPv4 (for now, focusing on IPv4)
            if not isinstance(ip, ipaddress.IPv4Address):
                return False

            # Accept both public AND private IPs (exclude only loopback/multicast/reserved)
            return not (
                ip.is_loopback or
                ip.is_multicast or
                ip.is_reserved or
                ip.is_link_local
            )

        except ValueError:
            return False

    @lru_cache(maxsize=10000)
    def _is_valid_public_ip(self, ip_str: str) -> bool:
        """Check if IP is valid and public (kept for backward compatibility)."""
        try:
            ip = ipaddress.ip_address(ip_str)

            # Check if it's IPv4 (for now, focusing on IPv4)
            if not isinstance(ip, ipaddress.IPv4Address):
                return False

            # Check if it's public
            return not (
                ip.is_private or
                ip.is_loopback or
                ip.is_multicast or
                ip.is_reserved or
                ip.is_link_local
            )

        except ValueError:
            return False
