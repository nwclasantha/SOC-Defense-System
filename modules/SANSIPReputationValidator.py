"""
SANS ISC IP Reputation Validator
Integrates with SANS Internet Storm Center API for IP reputation validation

API Documentation: https://isc.sans.edu/api/
"""

import requests
import time
import json
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import logging
from pathlib import Path


class SANSIPReputationValidator:
    """
    Validates IP addresses using SANS ISC API
    Provides reputation scores and threat intelligence data
    """

    def __init__(self, cache_dir: str = "./cache/sans_isc", cache_ttl_hours: int = 24):
        """
        Initialize SANS ISC validator

        Args:
            cache_dir: Directory to store cached API responses
            cache_ttl_hours: Cache time-to-live in hours (default 24h)
        """
        self.api_base = "https://isc.sans.edu/api/ip"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)

        self.logger = logging.getLogger(self.__class__.__name__)

        # Rate limiting (SANS ISC allows reasonable rate)
        self.last_request_time = 0
        self.min_request_interval = 1.0  # 1 second between requests

    def _get_cache_path(self, ip_address: str) -> Path:
        """Get cache file path for an IP address"""
        safe_ip = ip_address.replace('.', '_').replace(':', '_')
        return self.cache_dir / f"{safe_ip}.json"

    def _load_from_cache(self, ip_address: str) -> Optional[Dict]:
        """Load IP reputation from cache if not expired"""
        cache_file = self._get_cache_path(ip_address)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)

            # Check if cache is expired
            cached_time = datetime.fromisoformat(cached_data.get('cached_at', '2000-01-01'))
            if datetime.now() - cached_time > self.cache_ttl:
                self.logger.debug(f"Cache expired for {ip_address}")
                return None

            self.logger.debug(f"Loaded {ip_address} from cache")
            return cached_data.get('data')

        except Exception as e:
            self.logger.warning(f"Error loading cache for {ip_address}: {e}")
            return None

    def _save_to_cache(self, ip_address: str, data: Dict):
        """Save IP reputation to cache"""
        cache_file = self._get_cache_path(ip_address)

        try:
            cache_data = {
                'cached_at': datetime.now().isoformat(),
                'ip_address': ip_address,
                'data': data
            }

            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)

            self.logger.debug(f"Cached data for {ip_address}")

        except Exception as e:
            self.logger.warning(f"Error caching data for {ip_address}: {e}")

    def _rate_limit(self):
        """Enforce rate limiting between API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def query_ip(self, ip_address: str, use_cache: bool = True) -> Optional[Dict]:
        """
        Query SANS ISC API for IP reputation

        Args:
            ip_address: IP address to query
            use_cache: Whether to use cached results

        Returns:
            Dict with reputation data or None if query failed
        """
        # Check cache first
        if use_cache:
            cached = self._load_from_cache(ip_address)
            if cached is not None:
                return cached

        # Rate limiting
        self._rate_limit()

        # Query API
        try:
            url = f"{self.api_base}/{ip_address}?json"
            self.logger.info(f"Querying SANS ISC API for {ip_address}")

            response = requests.get(url, timeout=10)
            response.raise_for_status()

            # Parse JSON response
            data = response.json()

            # Save to cache
            if use_cache:
                self._save_to_cache(ip_address, data)

            return data

        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout querying SANS ISC for {ip_address}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error querying SANS ISC for {ip_address}: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing SANS ISC response for {ip_address}: {e}")
            return None

    def get_reputation_score(self, ip_address: str) -> Tuple[Optional[int], Optional[Dict]]:
        """
        Get reputation score for an IP address

        Returns:
            Tuple of (reputation_score, details)
            reputation_score: 0-100 (0=benign, 100=malicious)
            details: Dict with SANS ISC data
        """
        data = self.query_ip(ip_address)

        if not data or 'ip' not in data:
            return None, None

        ip_data = data.get('ip', {})

        # Extract key metrics (handle None values)
        attacks = int(ip_data.get('attacks') or 0)
        count = int(ip_data.get('count') or 0)
        min_date = ip_data.get('mindate', '') or ''
        max_date = ip_data.get('maxdate', '') or ''

        # Calculate reputation score (0-100, higher = more malicious)
        score = 0

        # 1. Attack count (0-50 points)
        if attacks > 0:
            if attacks >= 1000:
                score += 50
            elif attacks >= 100:
                score += 40
            elif attacks >= 10:
                score += 30
            elif attacks >= 1:
                score += 20

        # 2. Report count (0-30 points)
        if count > 0:
            if count >= 100:
                score += 30
            elif count >= 10:
                score += 20
            elif count >= 1:
                score += 10

        # 3. Recent activity (0-20 points)
        if max_date:
            try:
                last_seen = datetime.strptime(max_date, '%Y-%m-%d')
                days_ago = (datetime.now() - last_seen).days

                if days_ago <= 7:
                    score += 20  # Active in last week
                elif days_ago <= 30:
                    score += 15  # Active in last month
                elif days_ago <= 90:
                    score += 10  # Active in last 3 months
                elif days_ago <= 365:
                    score += 5   # Active in last year
            except (ValueError, TypeError):
                pass

        details = {
            'attacks': attacks,
            'count': count,
            'min_date': min_date,
            'max_date': max_date,
            'as_name': ip_data.get('asname', 'Unknown'),
            'as_number': ip_data.get('asnum', 'Unknown'),
            'country': ip_data.get('country', 'Unknown'),
            'network': ip_data.get('network', 'Unknown'),
        }

        return score, details

    def is_malicious(self, ip_address: str, threshold: int = 50) -> Tuple[bool, Optional[Dict]]:
        """
        Check if IP is malicious according to SANS ISC

        Args:
            ip_address: IP to check
            threshold: Reputation score threshold (default 50)

        Returns:
            Tuple of (is_malicious, details)
        """
        score, details = self.get_reputation_score(ip_address)

        if score is None:
            return None, None  # Unable to determine

        is_bad = score >= threshold

        if details:
            details['reputation_score'] = score
            details['threshold'] = threshold
            details['verdict'] = 'MALICIOUS' if is_bad else 'BENIGN'

        return is_bad, details

    def validate_batch(self, ip_addresses: list, threshold: int = 50,
                      delay_between: float = 1.0) -> Dict[str, Dict]:
        """
        Validate a batch of IP addresses

        Args:
            ip_addresses: List of IPs to validate
            threshold: Reputation score threshold
            delay_between: Delay between requests (seconds)

        Returns:
            Dict mapping IP -> validation results
        """
        results = {}

        self.logger.info(f"Validating {len(ip_addresses)} IP addresses with SANS ISC")

        for i, ip in enumerate(ip_addresses, 1):
            self.logger.info(f"[{i}/{len(ip_addresses)}] Validating {ip}")

            is_bad, details = self.is_malicious(ip, threshold=threshold)

            results[ip] = {
                'is_malicious': is_bad,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }

            # Delay between requests
            if i < len(ip_addresses):
                time.sleep(delay_between)

        return results

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        cache_files = list(self.cache_dir.glob("*.json"))

        total = len(cache_files)
        valid = 0
        expired = 0

        for cache_file in cache_files:
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    cached_time = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))

                    if datetime.now() - cached_time <= self.cache_ttl:
                        valid += 1
                    else:
                        expired += 1
            except (IOError, json.JSONDecodeError, ValueError, KeyError):
                expired += 1

        return {
            'total_cached': total,
            'valid': valid,
            'expired': expired,
            'cache_dir': str(self.cache_dir),
            'ttl_hours': self.cache_ttl.total_seconds() / 3600
        }

    def clear_cache(self, expired_only: bool = True):
        """
        Clear cached data

        Args:
            expired_only: Only clear expired entries (default True)
        """
        cache_files = list(self.cache_dir.glob("*.json"))
        removed = 0

        for cache_file in cache_files:
            should_remove = False

            if expired_only:
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        cached_time = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))

                        if datetime.now() - cached_time > self.cache_ttl:
                            should_remove = True
                except (IOError, json.JSONDecodeError, ValueError, KeyError):
                    should_remove = True  # Remove corrupted files
            else:
                should_remove = True

            if should_remove:
                cache_file.unlink()
                removed += 1

        self.logger.info(f"Removed {removed} cache files")
        return removed


if __name__ == "__main__":
    # Test the validator
    logging.basicConfig(level=logging.INFO)

    validator = SANSIPReputationValidator()

    # Test with known malicious IP (example)
    test_ips = [
        "188.148.149.159",  # From our analysis
        "8.8.8.8",          # Google DNS (should be benign)
        "10.14.25.136",     # Internal IP (may not be in SANS)
    ]

    print("=" * 80)
    print("SANS ISC IP Reputation Validation Test")
    print("=" * 80)
    print()

    for ip in test_ips:
        print(f"Testing IP: {ip}")
        print("-" * 80)

        is_bad, details = validator.is_malicious(ip, threshold=50)

        if is_bad is None:
            print(f"  Status: UNKNOWN (no data from SANS ISC)")
        elif is_bad:
            print(f"  Status: MALICIOUS")
            print(f"  Reputation Score: {details.get('reputation_score', 0)}/100")
            print(f"  Attacks: {details.get('attacks', 0)}")
            print(f"  Reports: {details.get('count', 0)}")
            print(f"  Last Seen: {details.get('max_date', 'Unknown')}")
            print(f"  Country: {details.get('country', 'Unknown')}")
            print(f"  ASN: {details.get('as_number', 'Unknown')} ({details.get('as_name', 'Unknown')})")
        else:
            print(f"  Status: BENIGN")
            print(f"  Reputation Score: {details.get('reputation_score', 0)}/100")

        print()

    # Show cache stats
    stats = validator.get_cache_stats()
    print("=" * 80)
    print("Cache Statistics:")
    print("-" * 80)
    print(f"Total Cached: {stats['total_cached']}")
    print(f"Valid: {stats['valid']}")
    print(f"Expired: {stats['expired']}")
    print(f"TTL: {stats['ttl_hours']} hours")
    print()
