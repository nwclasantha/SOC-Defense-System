"""
IP Address Validation and Reputation Engine
Validates, enriches, and scores IP addresses with multiple validation layers
"""

import ipaddress
import socket
import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

@dataclass
class IPValidationResult:
    """Complete IP validation and reputation result"""
    ip_address: str
    is_valid: bool
    ip_type: str  # ipv4, ipv6, private, public, reserved
    is_public: bool
    is_private: bool
    is_reserved: bool
    is_loopback: bool
    is_multicast: bool

    # Geolocation
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    organization: Optional[str] = None

    # Reputation
    reputation_score: int = 0  # 0-100 (0=clean, 100=malicious)
    threat_level: str = "unknown"  # clean, low, medium, high, critical
    is_blacklisted: bool = False
    blacklist_sources: List[str] = field(default_factory=list)

    # Threat Intelligence
    is_tor_exit: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_known_scanner: bool = False
    is_known_attacker: bool = False
    abuse_confidence: int = 0

    # Activity
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_reports: int = 0

    # Validation metadata
    validation_time: str = field(default_factory=lambda: datetime.now().isoformat())
    validation_sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class IPValidationEngine:
    """Advanced IP validation and reputation checking"""

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

        # Known malicious IP patterns
        self.known_malicious_ranges = self._load_malicious_ranges()
        self.known_tor_exits = set()
        self.known_vpn_ranges = set()

        # Local cache
        self.validation_cache = {}

    def _load_malicious_ranges(self) -> List[str]:
        """Load known malicious IP ranges"""
        return [
            # Example ranges - in production, load from threat feeds
            "5.188.0.0/16",     # Known botnet range
            "45.142.120.0/21",  # Known scanner range
            "193.106.30.0/24",  # Known attack source
        ]

    def validate_ip(self, ip_str: str, deep_check: bool = True) -> IPValidationResult:
        """Comprehensive IP validation and reputation check"""

        # Check cache first
        if ip_str in self.validation_cache:
            cached = self.validation_cache[ip_str]
            # Return cached if less than 1 hour old
            cached_time = datetime.fromisoformat(cached.validation_time)
            if (datetime.now() - cached_time).seconds < 3600:
                return cached

        result = IPValidationResult(
            ip_address=ip_str,
            is_valid=False,
            ip_type="invalid",
            is_public=False,
            is_private=False,
            is_reserved=False,
            is_loopback=False,
            is_multicast=False
        )

        try:
            # Basic IP validation
            ip_obj = ipaddress.ip_address(ip_str)
            result.is_valid = True
            result.validation_sources.append("ipaddress_module")

            # Determine IP type
            if isinstance(ip_obj, ipaddress.IPv4Address):
                result.ip_type = "ipv4"
            else:
                result.ip_type = "ipv6"

            # Check IP characteristics
            result.is_private = ip_obj.is_private
            result.is_public = not ip_obj.is_private
            result.is_loopback = ip_obj.is_loopback
            result.is_multicast = ip_obj.is_multicast
            result.is_reserved = ip_obj.is_reserved

            # Only do deep checks for public IPs
            if result.is_public and deep_check:
                self._perform_deep_validation(result, ip_str, ip_obj)

            # Calculate reputation score
            result.reputation_score = self._calculate_reputation_score(result)
            result.threat_level = self._determine_threat_level(result.reputation_score)

        except ValueError as e:
            result.errors.append(f"Invalid IP format: {e}")
            self.logger.warning(f"Invalid IP address: {ip_str}")
        except Exception as e:
            result.errors.append(f"Validation error: {e}")
            self.logger.error(f"Error validating IP {ip_str}: {e}")

        # Cache result
        self.validation_cache[ip_str] = result

        return result

    def _perform_deep_validation(self, result: IPValidationResult,
                                 ip_str: str, ip_obj):
        """Perform deep validation checks"""

        # Check against malicious ranges
        for malicious_range in self.known_malicious_ranges:
            try:
                if ip_obj in ipaddress.ip_network(malicious_range):
                    result.is_blacklisted = True
                    result.blacklist_sources.append("local_malicious_ranges")
                    result.validation_sources.append("malicious_range_check")
                    break
            except (ValueError, TypeError):
                pass

        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            result.validation_sources.append("reverse_dns")

            # Check for suspicious patterns in hostname
            suspicious_keywords = ['tor', 'vpn', 'proxy', 'scanner', 'bot', 'exploit']
            hostname_lower = hostname.lower()

            if any(kw in hostname_lower for kw in suspicious_keywords):
                if 'tor' in hostname_lower:
                    result.is_tor_exit = True
                if 'vpn' in hostname_lower:
                    result.is_vpn = True
                if 'proxy' in hostname_lower:
                    result.is_proxy = True
                if any(kw in hostname_lower for kw in ['scanner', 'bot']):
                    result.is_known_scanner = True
        except socket.herror:
            # No reverse DNS - not necessarily bad
            pass
        except Exception as e:
            result.errors.append(f"Reverse DNS failed: {e}")

        # Check common attacker patterns
        result.is_known_attacker = self._check_attacker_patterns(ip_str)
        if result.is_known_attacker:
            result.validation_sources.append("attacker_pattern_match")

        # Simulate abuse confidence (in production, query AbuseIPDB API)
        result.abuse_confidence = self._estimate_abuse_confidence(result)

    def _check_attacker_patterns(self, ip_str: str) -> bool:
        """Check if IP matches known attacker patterns"""
        # Common attacker IP patterns
        attacker_patterns = [
            r'^45\.88\.',      # Common attack source range
            r'^45\.142\.',     # Scanner range
            r'^185\.220\.',    # Known Tor range
            r'^193\.106\.',    # Attack source
        ]

        for pattern in attacker_patterns:
            if re.match(pattern, ip_str):
                return True
        return False

    def _estimate_abuse_confidence(self, result: IPValidationResult) -> int:
        """Estimate abuse confidence based on indicators"""
        confidence = 0

        if result.is_blacklisted:
            confidence += 40
        if result.is_tor_exit:
            confidence += 20
        if result.is_known_attacker:
            confidence += 30
        if result.is_known_scanner:
            confidence += 25
        if result.is_vpn or result.is_proxy:
            confidence += 10

        return min(confidence, 100)

    def _calculate_reputation_score(self, result: IPValidationResult) -> int:
        """Calculate overall reputation score (0=clean, 100=malicious)"""
        score = 0

        # Private/local IPs are safe
        if result.is_private or result.is_loopback:
            return 0

        # Blacklisted IPs
        if result.is_blacklisted:
            score += 50

        # Known bad actors
        if result.is_known_attacker:
            score += 40

        # Suspicious infrastructure
        if result.is_tor_exit:
            score += 30
        if result.is_known_scanner:
            score += 35
        if result.is_vpn:
            score += 15
        if result.is_proxy:
            score += 20

        # Abuse confidence
        score += result.abuse_confidence // 2

        return min(score, 100)

    def _determine_threat_level(self, reputation_score: int) -> str:
        """Determine threat level from reputation score"""
        if reputation_score >= 85:
            return "critical"
        elif reputation_score >= 70:
            return "high"
        elif reputation_score >= 40:
            return "medium"
        elif reputation_score >= 20:
            return "low"
        else:
            return "clean"

    def validate_multiple_ips(self, ip_list: List[str],
                             deep_check: bool = True) -> Dict[str, IPValidationResult]:
        """Validate multiple IP addresses"""
        results = {}

        for ip in ip_list:
            results[ip] = self.validate_ip(ip, deep_check)

        return results

    def get_validation_summary(self, results: Dict[str, IPValidationResult]) -> Dict:
        """Get summary statistics from validation results"""
        total = len(results)
        valid = sum(1 for r in results.values() if r.is_valid)
        public = sum(1 for r in results.values() if r.is_public)
        private = sum(1 for r in results.values() if r.is_private)
        blacklisted = sum(1 for r in results.values() if r.is_blacklisted)

        threat_levels = {
            'clean': sum(1 for r in results.values() if r.threat_level == 'clean'),
            'low': sum(1 for r in results.values() if r.threat_level == 'low'),
            'medium': sum(1 for r in results.values() if r.threat_level == 'medium'),
            'high': sum(1 for r in results.values() if r.threat_level == 'high'),
            'critical': sum(1 for r in results.values() if r.threat_level == 'critical'),
        }

        return {
            'total_ips': total,
            'valid_ips': valid,
            'invalid_ips': total - valid,
            'public_ips': public,
            'private_ips': private,
            'blacklisted': blacklisted,
            'threat_levels': threat_levels,
            'average_reputation': sum(r.reputation_score for r in results.values()) / total if total > 0 else 0
        }

    def export_results(self, results: Dict[str, IPValidationResult],
                      filename: str = "ip_validation_results.json"):
        """Export validation results to JSON"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_ips': len(results),
            'results': {
                ip: {
                    'ip_address': r.ip_address,
                    'is_valid': r.is_valid,
                    'ip_type': r.ip_type,
                    'is_public': r.is_public,
                    'reputation_score': r.reputation_score,
                    'threat_level': r.threat_level,
                    'is_blacklisted': r.is_blacklisted,
                    'is_tor_exit': r.is_tor_exit,
                    'is_vpn': r.is_vpn,
                    'is_proxy': r.is_proxy,
                    'is_known_scanner': r.is_known_scanner,
                    'is_known_attacker': r.is_known_attacker,
                    'abuse_confidence': r.abuse_confidence,
                }
                for ip, r in results.items()
            }
        }

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            self.logger.info(f"Exported validation results to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            return False

    def get_high_risk_ips(self, results: Dict[str, IPValidationResult],
                         min_score: int = 60) -> List[IPValidationResult]:
        """Get IPs with reputation score above threshold"""
        return [r for r in results.values()
                if r.reputation_score >= min_score]

    def get_blacklisted_ips(self, results: Dict[str, IPValidationResult]) -> List[IPValidationResult]:
        """Get all blacklisted IPs"""
        return [r for r in results.values() if r.is_blacklisted]

    def get_anonymous_ips(self, results: Dict[str, IPValidationResult]) -> List[IPValidationResult]:
        """Get IPs using anonymization (Tor/VPN/Proxy)"""
        return [r for r in results.values()
                if r.is_tor_exit or r.is_vpn or r.is_proxy]

    def get_public_ips(self, results: Dict[str, IPValidationResult]) -> List[IPValidationResult]:
        """Get all public IPs only"""
        return [r for r in results.values() if r.is_public]

    def get_private_ips(self, results: Dict[str, IPValidationResult]) -> List[IPValidationResult]:
        """Get all private IPs only"""
        return [r for r in results.values() if r.is_private]

    def get_attacker_ips(self, results: Dict[str, IPValidationResult]) -> List[IPValidationResult]:
        """Get all IPs marked as attackers (public or private)"""
        return [r for r in results.values() if r.is_known_attacker]
