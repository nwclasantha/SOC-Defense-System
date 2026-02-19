"""
SANS ISC (Internet Storm Center) Validator
Validates IPs against SANS ISC threat database for ground truth labeling

Author: SOC Defense System
Version: 1.0.0
"""

import requests
import json
import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
import hashlib


class SANSISCValidator:
    """
    Validates IP addresses against SANS Internet Storm Center API

    API Documentation: https://isc.sans.edu/api/

    Features:
    - Query IP reputation from SANS ISC
    - Cache results to minimize API calls
    - Batch validation support
    - Ground truth labeling for ML training
    """

    SANS_ISC_API_BASE = "https://isc.sans.edu/api"
    CACHE_TTL_HOURS = 24

    def __init__(self, cache_dir: str = "./cache/sans_isc"):
        """
        Initialize SANS ISC validator

        Args:
            cache_dir: Directory for caching API responses
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SOC-Defense-System/1.0'
        })
        # Fast-fail mechanism
        self._consecutive_failures = 0
        self._max_failures_before_skip = 2  # Skip after 2 consecutive failures
        self._skip_until = None  # Timestamp when to retry
        self._skip_duration_seconds = 60  # Skip for 60 seconds after failures

        # Rate limiting: 1 request per second (60/minute)
        self._min_request_interval = 1.0  # seconds between API calls
        self._last_request_time = 0.0

    def validate_ip(self, ip_address: str) -> Dict[str, any]:
        """
        Validate a single IP address against SANS ISC

        Args:
            ip_address: IP address to validate

        Returns:
            Dictionary with validation results:
            {
                'ip': str,
                'is_malicious': bool,
                'threat_score': float (0-100),
                'attack_count': int,
                'first_seen': str,
                'last_seen': str,
                'confidence': float (0-1),
                'source': 'SANS ISC',
                'raw_data': dict
            }
        """
        # Check cache first
        cache_data = self._get_from_cache(ip_address)
        if cache_data:
            self.logger.debug(f"Cache hit for {ip_address}")
            return cache_data

        # Fast-fail: Check if we should skip API calls due to consecutive failures
        if self._skip_until and datetime.now() < self._skip_until:
            self.logger.debug(f"Skipping SANS ISC for {ip_address} - in cooldown period")
            return self._get_unknown_result(ip_address)

        # Rate limiting: wait if needed
        import time
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

        # Query SANS ISC API
        self.logger.debug(f"Querying SANS ISC for {ip_address}")
        try:
            url = f"{self.SANS_ISC_API_BASE}/ip/{ip_address}?json"
            response = self.session.get(url, timeout=30)  # 30 second timeout for reliability

            if response.status_code == 200:
                data = response.json()
                result = self._parse_sans_response(ip_address, data)

                # Cache result
                self._save_to_cache(ip_address, result)

                # Reset failure counter on success
                self._consecutive_failures = 0
                self._skip_until = None

                return result
            else:
                self.logger.warning(f"SANS ISC API returned status {response.status_code} for {ip_address}")
                self._record_failure()
                return self._get_unknown_result(ip_address)

        except requests.exceptions.Timeout:
            self.logger.warning(f"SANS ISC timeout for {ip_address} - skipping")
            self._record_failure()
            return self._get_unknown_result(ip_address)
        except requests.exceptions.ConnectionError:
            self.logger.warning(f"SANS ISC connection error for {ip_address} - skipping")
            self._record_failure()
            return self._get_unknown_result(ip_address)
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"SANS ISC request failed for {ip_address}: {e}")
            self._record_failure()
            return self._get_unknown_result(ip_address)

    def _record_failure(self):
        """Record a failure and potentially enable skip mode"""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._max_failures_before_skip:
            self._skip_until = datetime.now() + timedelta(seconds=self._skip_duration_seconds)
            self.logger.warning(f"SANS ISC: {self._consecutive_failures} consecutive failures - skipping for {self._skip_duration_seconds}s")

    def validate_batch(self, ip_addresses: List[str], delay_seconds: float = 1.0) -> Dict[str, Dict]:
        """
        Validate multiple IP addresses

        Args:
            ip_addresses: List of IP addresses to validate
            delay_seconds: Delay between API calls to respect rate limits

        Returns:
            Dictionary mapping IP addresses to validation results
        """
        import time

        results = {}
        for i, ip in enumerate(ip_addresses):
            results[ip] = self.validate_ip(ip)

            # Add delay between requests (except for cached results)
            if i < len(ip_addresses) - 1:
                if not results[ip].get('cached', False):
                    time.sleep(delay_seconds)

        self.logger.info(f"Validated {len(ip_addresses)} IPs against SANS ISC")
        return results

    def get_ground_truth_labels(self, ip_addresses: List[str],
                                threshold: int = 10) -> Dict[str, bool]:
        """
        Get binary ground truth labels for ML training

        Args:
            ip_addresses: List of IP addresses
            threshold: Minimum attack count to consider malicious

        Returns:
            Dictionary mapping IP addresses to malicious status (True/False)
        """
        validation_results = self.validate_batch(ip_addresses)

        labels = {}
        for ip, result in validation_results.items():
            # Label as malicious if attack count >= threshold
            is_malicious = result.get('attack_count', 0) >= threshold
            labels[ip] = is_malicious

        malicious_count = sum(labels.values())
        benign_count = len(labels) - malicious_count

        self.logger.info(f"Ground truth labels: {malicious_count} malicious, {benign_count} benign")

        return labels

    def _parse_sans_response(self, ip_address: str, data: Dict) -> Dict:
        """Parse SANS ISC API response"""
        result = {
            'ip': ip_address,
            'is_malicious': False,
            'threat_score': 0,
            'attack_count': 0,
            'first_seen': None,
            'last_seen': None,
            'confidence': 0.0,
            'source': 'SANS ISC',
            'raw_data': data,
            'cached': False,
            'timestamp': datetime.now().isoformat()
        }

        # Parse IP data
        if 'ip' in data and isinstance(data['ip'], dict):
            ip_data = data['ip']

            # Attack count
            attack_count = ip_data.get('count', 0)
            result['attack_count'] = int(attack_count) if attack_count is not None else 0

            # Reports/attacks
            attacks_raw = ip_data.get('attacks', 0)
            attacks = int(attacks_raw) if attacks_raw is not None else 0
            result['attacks'] = attacks

            # Dates
            result['first_seen'] = ip_data.get('mindate')
            result['last_seen'] = ip_data.get('maxdate')

            # Calculate threat score (0-100)
            if attacks > 10000:
                result['threat_score'] = 100
                result['confidence'] = 0.95
            elif attacks > 1000:
                result['threat_score'] = 85
                result['confidence'] = 0.90
            elif attacks > 100:
                result['threat_score'] = 70
                result['confidence'] = 0.80
            elif attacks > 10:
                result['threat_score'] = 50
                result['confidence'] = 0.70
            elif attacks > 0:
                result['threat_score'] = 30
                result['confidence'] = 0.60
            else:
                result['threat_score'] = 0
                result['confidence'] = 0.50  # Unknown, not seen attacking

            # Malicious determination (conservative)
            # Only mark as malicious if seen attacking at least 10 times
            result['is_malicious'] = attacks >= 10

            # Additional metadata
            result['as_number'] = ip_data.get('asabusecontact')
            result['network'] = ip_data.get('network')
            comment_count = ip_data.get('comment', 0)
            result['comment_count'] = int(comment_count) if comment_count is not None else 0

        return result

    def _get_unknown_result(self, ip_address: str) -> Dict:
        """Return result for unknown/failed queries"""
        return {
            'ip': ip_address,
            'is_malicious': False,
            'threat_score': 0,
            'attack_count': 0,
            'first_seen': None,
            'last_seen': None,
            'confidence': 0.0,
            'source': 'SANS ISC',
            'error': 'Query failed or no data available',
            'cached': False,
            'timestamp': datetime.now().isoformat()
        }

    def _get_from_cache(self, ip_address: str) -> Optional[Dict]:
        """Retrieve IP data from cache if not expired"""
        cache_key = hashlib.md5(ip_address.encode()).hexdigest()
        cache_file = self.cache_dir / f"sans_{cache_key}.json"

        if cache_file.exists():
            # Check if cache is still valid
            file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if file_age < timedelta(hours=self.CACHE_TTL_HOURS):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data['cached'] = True
                        return data
                except Exception as e:
                    self.logger.warning(f"Failed to read cache for {ip_address}: {e}")

        return None

    def _save_to_cache(self, ip_address: str, data: Dict):
        """Save IP data to cache"""
        cache_key = hashlib.md5(ip_address.encode()).hexdigest()
        cache_file = self.cache_dir / f"sans_{cache_key}.json"

        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to cache data for {ip_address}: {e}")

    def get_statistics(self, ip_addresses: List[str]) -> Dict:
        """Get aggregate statistics for a list of IPs"""
        results = self.validate_batch(ip_addresses)

        stats = {
            'total_ips': len(ip_addresses),
            'malicious_count': 0,
            'benign_count': 0,
            'unknown_count': 0,
            'total_attacks': 0,
            'avg_threat_score': 0.0,
            'high_confidence_malicious': 0,  # confidence >= 0.8
        }

        threat_scores = []
        for result in results.values():
            if result.get('is_malicious'):
                stats['malicious_count'] += 1
            elif result.get('attack_count', 0) == 0:
                stats['unknown_count'] += 1
            else:
                stats['benign_count'] += 1

            stats['total_attacks'] += result.get('attack_count', 0)
            threat_scores.append(result.get('threat_score', 0))

            if result.get('is_malicious') and result.get('confidence', 0) >= 0.8:
                stats['high_confidence_malicious'] += 1

        if threat_scores:
            stats['avg_threat_score'] = sum(threat_scores) / len(threat_scores)

        stats['malicious_percentage'] = (stats['malicious_count'] / stats['total_ips'] * 100) if stats['total_ips'] > 0 else 0

        return stats

    def clear_cache(self, older_than_hours: Optional[int] = None):
        """
        Clear cached data

        Args:
            older_than_hours: Only clear cache older than this many hours (None = clear all)
        """
        cleared_count = 0

        for cache_file in self.cache_dir.glob("sans_*.json"):
            if older_than_hours is None:
                cache_file.unlink()
                cleared_count += 1
            else:
                file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
                if file_age > timedelta(hours=older_than_hours):
                    cache_file.unlink()
                    cleared_count += 1

        self.logger.info(f"Cleared {cleared_count} cached entries")
        return cleared_count
