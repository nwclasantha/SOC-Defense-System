import logging
import aiohttp
import asyncio
import time
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from pathlib import Path
import ipaddress

# Module imports
from modules.CacheManager import CacheManager


class ThreatIntelPersistentCache:
    """
    Persistent file-based cache for individual API responses.

    Features:
    - Separate cache directories for each API source
    - Intelligent TTL based on threat level:
      - Clean IPs: 72 hours (less likely to change)
      - Suspicious IPs: 24 hours (moderate refresh)
      - Malicious IPs: 12 hours (need fresher data for active threats)
    - Hash-based filename for safe storage
    - Automatic cache cleanup for expired entries
    """

    # TTL settings in hours based on threat level (EXTENDED for speed)
    TTL_CLEAN = 168      # Clean IPs - 1 week (they rarely change)
    TTL_SUSPICIOUS = 72  # Some activity - 3 days
    TTL_MALICIOUS = 24   # Active threats - 1 day (still need relatively fresh)

    def __init__(self, cache_dir: str = "./cache/threat_intel"):
        self.cache_dir = Path(cache_dir)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Create separate directories for each API
        self.virustotal_dir = self.cache_dir / "virustotal"
        self.abuseipdb_dir = self.cache_dir / "abuseipdb"

        # Ensure directories exist
        self.virustotal_dir.mkdir(parents=True, exist_ok=True)
        self.abuseipdb_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info(f"Persistent cache initialized at {self.cache_dir}")

        # Track cache stats
        self._cache_hits = 0
        self._cache_misses = 0

    def _get_cache_path(self, source: str, ip_address: str) -> Path:
        """Get cache file path for an IP address"""
        # Use MD5 hash to create safe filename
        ip_hash = hashlib.md5(ip_address.encode()).hexdigest()

        if source == "virustotal":
            return self.virustotal_dir / f"{ip_hash}.json"
        elif source == "abuseipdb":
            return self.abuseipdb_dir / f"{ip_hash}.json"
        else:
            raise ValueError(f"Unknown source: {source}")

    def _get_ttl_hours(self, data: Dict[str, Any], source: str) -> int:
        """Determine TTL based on threat level of the response"""
        if source == "virustotal":
            malicious_count = data.get('malicious_count', 0)
            suspicious_count = data.get('suspicious_count', 0)

            if malicious_count > 0:
                return self.TTL_MALICIOUS
            elif suspicious_count > 0:
                return self.TTL_SUSPICIOUS
            else:
                return self.TTL_CLEAN

        elif source == "abuseipdb":
            abuse_score = data.get('abuse_confidence_score', 0)

            if abuse_score >= 50:
                return self.TTL_MALICIOUS
            elif abuse_score >= 25:
                return self.TTL_SUSPICIOUS
            else:
                return self.TTL_CLEAN

        return self.TTL_SUSPICIOUS  # Default

    def get(self, source: str, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get cached API response for an IP address.

        Returns None if cache miss or expired.
        """
        cache_path = self._get_cache_path(source, ip_address)

        if not cache_path.exists():
            self._cache_misses += 1
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_entry = json.load(f)

            # Check expiry
            cached_at = datetime.fromisoformat(cache_entry.get('cached_at', '2000-01-01'))
            ttl_hours = cache_entry.get('ttl_hours', self.TTL_SUSPICIOUS)
            expiry_time = cached_at + timedelta(hours=ttl_hours)

            if datetime.now() > expiry_time:
                # Cache expired - delete and return None
                self.logger.debug(f"Cache expired for {source}:{ip_address}")
                cache_path.unlink(missing_ok=True)
                self._cache_misses += 1
                return None

            self._cache_hits += 1
            self.logger.debug(f"Cache HIT for {source}:{ip_address} (expires in {(expiry_time - datetime.now()).total_seconds()/3600:.1f}h)")
            return cache_entry.get('data')

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            self.logger.warning(f"Cache read error for {source}:{ip_address}: {e}")
            cache_path.unlink(missing_ok=True)
            self._cache_misses += 1
            return None

    def set(self, source: str, ip_address: str, data: Dict[str, Any]) -> None:
        """
        Cache API response with intelligent TTL based on threat level.
        """
        cache_path = self._get_cache_path(source, ip_address)
        ttl_hours = self._get_ttl_hours(data, source)

        cache_entry = {
            'ip': ip_address,
            'source': source,
            'data': data,
            'cached_at': datetime.now().isoformat(),
            'ttl_hours': ttl_hours
        }

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_entry, f, indent=2, default=str)

            self.logger.debug(f"Cached {source}:{ip_address} (TTL: {ttl_hours}h)")

        except IOError as e:
            self.logger.error(f"Cache write error for {source}:{ip_address}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total * 100) if total > 0 else 0

        # Count cached files
        vt_count = len(list(self.virustotal_dir.glob("*.json")))
        abuse_count = len(list(self.abuseipdb_dir.glob("*.json")))

        return {
            'cache_hits': self._cache_hits,
            'cache_misses': self._cache_misses,
            'hit_rate_percent': round(hit_rate, 1),
            'virustotal_cached_ips': vt_count,
            'abuseipdb_cached_ips': abuse_count,
            'cache_directory': str(self.cache_dir)
        }

    def cleanup_expired(self) -> int:
        """Remove all expired cache entries. Returns count of removed entries."""
        removed_count = 0

        for cache_dir in [self.virustotal_dir, self.abuseipdb_dir]:
            for cache_file in cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_entry = json.load(f)

                    cached_at = datetime.fromisoformat(cache_entry.get('cached_at', '2000-01-01'))
                    ttl_hours = cache_entry.get('ttl_hours', self.TTL_SUSPICIOUS)

                    if datetime.now() > cached_at + timedelta(hours=ttl_hours):
                        cache_file.unlink()
                        removed_count += 1

                except (json.JSONDecodeError, IOError):
                    # Remove corrupted cache files
                    cache_file.unlink(missing_ok=True)
                    removed_count += 1

        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} expired cache entries")

        return removed_count

    def clear_all(self) -> int:
        """Clear all cached entries. Returns count of removed entries."""
        removed_count = 0

        for cache_dir in [self.virustotal_dir, self.abuseipdb_dir]:
            for cache_file in cache_dir.glob("*.json"):
                cache_file.unlink()
                removed_count += 1

        self._cache_hits = 0
        self._cache_misses = 0

        self.logger.info(f"Cleared all {removed_count} cache entries")
        return removed_count


from modules.ExponentialBackoff import RetryConfig, ExponentialBackoff, BackoffStrategy
from modules.CircuitBreaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenException, CircuitBreakerRegistry, CircuitState
from modules.DeadLetterQueue import DeadLetterQueue, DLQEventPriority
from modules.SANSISCValidator import SANSISCValidator


class AsyncRateLimiter:
    """
    Token bucket rate limiter for API calls.

    VirusTotal Free: 4 requests/minute (1 every 15 seconds)
    AbuseIPDB Free: 1000 requests/day (~42/hour, 1 every ~85 seconds to be safe)
    """

    def __init__(self, requests_per_minute: float, name: str = ""):
        self.name = name
        # Ensure requests_per_minute is at least 0.1 to avoid division by zero
        self.requests_per_minute = max(requests_per_minute, 0.1)
        self.min_interval = 60.0 / self.requests_per_minute  # seconds between requests
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger(f"RateLimiter.{name}")

    async def acquire(self):
        """Wait until we can make another request"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time

            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                self.logger.debug(f"{self.name}: Rate limiting - waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)

            self.last_request_time = time.time()

class ThreatIntelligenceEnricher:
    """
    Enhanced threat intelligence enrichment with comprehensive error handling

    Features:
    - Multi-source threat intelligence (VirusTotal, AbuseIPDB, OTX)
    - Exponential backoff for API rate limiting
    - Circuit breaker for failing services
    - Dead letter queue for failed enrichments
    - Intelligent caching
    """

    def __init__(
        self,
        cache_manager: Optional[CacheManager] = None,
        virustotal_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        enable_sans_isc: bool = True,
        enable_error_handling: bool = True,
        virustotal_rpm: float = 4.0,   # VirusTotal free tier: 4 requests/minute
        abuseipdb_rpm: float = 30.0,   # AbuseIPDB free: 1000/day - 30/min burst is safe (uses ~1800/day at max)
        sans_isc_rpm: float = 60.0,    # SANS ISC: ~1 req/sec recommended (60/min)
        enable_virustotal: bool = True,  # Set False to disable VirusTotal
        enable_abuseipdb: bool = True    # Set False to disable AbuseIPDB
    ):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cache = cache_manager

        # Store enable flags
        self.enable_virustotal = enable_virustotal
        self.enable_abuseipdb = enable_abuseipdb
        self.enable_sans_isc = enable_sans_isc
        self.enable_error_handling = enable_error_handling

        # Default circuit breaker/error handling attributes (set properly if enable_error_handling=True)
        self.vt_breaker = None
        self.abuse_breaker = None
        self.backoff = None
        self.dlq = None

        # Disable APIs based on flags (e.g., daily quota exceeded)
        self.virustotal_api_key = virustotal_api_key if enable_virustotal else None
        self.abuseipdb_api_key = abuseipdb_api_key if enable_abuseipdb else None

        # Log disabled APIs
        disabled_apis = []
        if not enable_virustotal:
            disabled_apis.append("VirusTotal")
        if not enable_abuseipdb:
            disabled_apis.append("AbuseIPDB")
        if not enable_sans_isc:
            disabled_apis.append("SANS ISC")

        if disabled_apis:
            self.logger.warning("=" * 50)
            self.logger.warning(f"DISABLED APIs: {', '.join(disabled_apis)}")
            self.logger.warning("=" * 50)

        # Rate limiters to respect API quotas
        self.vt_rate_limiter = AsyncRateLimiter(virustotal_rpm, "VirusTotal")
        self.abuse_rate_limiter = AsyncRateLimiter(abuseipdb_rpm, "AbuseIPDB")
        self.sans_rate_limiter = AsyncRateLimiter(sans_isc_rpm, "SANS_ISC")

        # Log enabled APIs
        enabled_apis = []
        if enable_virustotal and virustotal_api_key:
            enabled_apis.append(f"VirusTotal ({virustotal_rpm}/min)")
        if enable_abuseipdb and abuseipdb_api_key:
            enabled_apis.append(f"AbuseIPDB ({abuseipdb_rpm}/min)")
        if enable_sans_isc:
            enabled_apis.append(f"SANS ISC ({sans_isc_rpm}/min)")
        self.logger.info(f"Enabled APIs: {', '.join(enabled_apis) if enabled_apis else 'None'}")

        # Initialize SANS ISC validator
        if enable_sans_isc:
            self.sans_validator = SANSISCValidator()
            self.logger.info("SANS ISC validator initialized")
        else:
            self.sans_validator = None

        # Initialize persistent cache for individual API responses
        self.persistent_cache = ThreatIntelPersistentCache()
        self.logger.info("Persistent API cache initialized (VT/AbuseIPDB)")

        # Initialize error handling
        if enable_error_handling:
            self._init_error_handling()

    def _init_error_handling(self) -> None:
        """Initialize error handling components"""
        # Retry configuration for API calls - optimized for fast failure
        self.retry_config = RetryConfig(
            max_attempts=1,  # No retries - fail fast when network is down
            initial_delay=0.5,
            max_delay=5.0,  # Reduced from 60s
            exponential_base=2.0,
            jitter=True,
            strategy=BackoffStrategy.EXPONENTIAL,
            retry_on_exceptions=(
                aiohttp.ClientError,
                aiohttp.ServerTimeoutError,
                TimeoutError,
                ConnectionError
            ),
            fatal_exceptions=(
                ValueError,  # Invalid IP
            ),
            max_retries_per_minute=50  # Increased to avoid budget exhaustion
        )
        self.backoff = ExponentialBackoff(self.retry_config)

        # Circuit breakers for each service
        registry = CircuitBreakerRegistry.get_instance()

        # VirusTotal circuit breaker - balanced for batch processing
        vt_config = CircuitBreakerConfig(
            failure_threshold=5,  # Allow 5 failures before opening (for batch processing)
            failure_rate_threshold=0.3,  # Open if 30% of calls fail
            reset_timeout=120.0,  # Wait 2 minutes before retrying after open
            half_open_max_calls=2,
            on_open=lambda: self.logger.warning("VirusTotal circuit breaker OPENED - skipping API calls"),
            on_close=lambda: self.logger.info("VirusTotal circuit breaker CLOSED")
        )
        self.vt_breaker = registry.get_or_create("virustotal", vt_config)

        # AbuseIPDB circuit breaker - balanced for batch processing
        abuse_config = CircuitBreakerConfig(
            failure_threshold=5,  # Allow 5 failures before opening (for batch processing)
            failure_rate_threshold=0.3,  # Open if 30% of calls fail
            reset_timeout=120.0,  # Wait 2 minutes before retrying after open
            half_open_max_calls=2,
            on_open=lambda: self.logger.warning("AbuseIPDB circuit breaker OPENED - skipping API calls"),
            on_close=lambda: self.logger.info("AbuseIPDB circuit breaker CLOSED")
        )
        self.abuse_breaker = registry.get_or_create("abuseipdb", abuse_config)

        # Dead letter queue
        self.dlq = DeadLetterQueue(
            db_path="dlq/threat_intel_dlq.db",
            auto_process=False
        )

        self.logger.info("Error handling initialized for Threat Intelligence Enricher")

    async def enrich(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich IP with threat intelligence from multiple sources

        Args:
            ip_address: IP address to enrich

        Returns:
            Threat intelligence data or None
        """
        # Validate IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip_address}")
            return None

        # Build cache key that includes enabled APIs (so cache is invalidated when settings change)
        enabled_apis = []
        if self.enable_virustotal and self.virustotal_api_key:
            enabled_apis.append('VT')
        if self.enable_abuseipdb and self.abuseipdb_api_key:
            enabled_apis.append('ABUSE')
        if self.enable_sans_isc:
            enabled_apis.append('SANS')
        api_config_hash = '_'.join(sorted(enabled_apis)) if enabled_apis else 'NONE'

        # Check cache with API-aware key
        if self.cache:
            cache_key = f"threat_intel:{ip_address}:{api_config_hash}"
            cached_data = self.cache.get(cache_key)
            if cached_data:
                self.logger.debug(f"Cache hit for {ip_address} (APIs: {api_config_hash})")
                return cached_data

        # Aggregate threat intelligence from multiple sources
        threat_data = await self._aggregate_threat_intel(ip_address)

        if threat_data:
            # Cache the result (24 hour TTL) with API-aware key
            if self.cache:
                self.cache.set(cache_key, threat_data, ttl=86400)

        return threat_data

    async def _aggregate_threat_intel(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Aggregate threat intelligence from multiple sources IN PARALLEL"""
        sources = []
        errors = []

        # Build list of API tasks to run in parallel
        api_tasks = []

        # VirusTotal task
        async def query_vt():
            if not self.virustotal_api_key:
                return None
            if self.enable_error_handling and self.vt_breaker and self.vt_breaker.state != CircuitState.CLOSED:
                self.logger.debug(f"Skipping VirusTotal for {ip_address} - circuit breaker {self.vt_breaker.state.value}")
                return None
            try:
                return await self._query_virustotal(ip_address)
            except Exception as e:
                self.logger.warning(f"VirusTotal query failed for {ip_address}: {e}")
                errors.append(("VirusTotal", str(e)))
                return None

        # AbuseIPDB task
        async def query_abuse():
            if not self.abuseipdb_api_key:
                return None
            if self.enable_error_handling and self.abuse_breaker and self.abuse_breaker.state != CircuitState.CLOSED:
                self.logger.debug(f"Skipping AbuseIPDB for {ip_address} - circuit breaker {self.abuse_breaker.state.value}")
                return None
            try:
                return await self._query_abuseipdb(ip_address)
            except Exception as e:
                self.logger.warning(f"AbuseIPDB query failed for {ip_address}: {e}")
                errors.append(("AbuseIPDB", str(e)))
                return None

        # SANS ISC task (wrap sync call in async)
        async def query_sans():
            if not self.sans_validator:
                return None
            try:
                # Run sync SANS validator in thread pool to not block
                loop = asyncio.get_running_loop()
                sans_data = await loop.run_in_executor(None, self.sans_validator.validate_ip, ip_address)
                if sans_data and sans_data.get('attack_count', 0) > 0:
                    return {
                        'source': 'SANS_ISC',
                        'threat_score': sans_data.get('threat_score', 0),
                        'attack_count': sans_data.get('attack_count', 0),
                        'attacks': sans_data.get('attacks', 0),
                        'is_malicious': sans_data.get('is_malicious', False),
                        'confidence': sans_data.get('confidence', 0),
                        'first_seen': sans_data.get('first_seen'),
                        'last_seen': sans_data.get('last_seen')
                    }
                return None
            except Exception as e:
                self.logger.warning(f"SANS ISC query failed for {ip_address}: {e}")
                errors.append(("SANS_ISC", str(e)))
                return None

        # Run ALL API queries in PARALLEL (huge speedup!)
        results = await asyncio.gather(query_vt(), query_abuse(), query_sans(), return_exceptions=True)

        # Collect successful results
        for result in results:
            if result and not isinstance(result, Exception):
                sources.append(result)

        # If no sources succeeded, return None
        if not sources:
            if errors:
                # Add to DLQ for later retry
                if self.enable_error_handling:
                    self.dlq.add_event(
                        event_type="threat_intel_enrichment",
                        payload={"ip": ip_address},
                        error=Exception(f"All threat intel sources failed: {errors}"),
                        source="ThreatIntelligenceEnricher",
                        priority=DLQEventPriority.LOW,
                        max_retries=3,
                        ttl_hours=72
                    )
                # Return partial result with error info instead of None
                self.logger.error(f"All threat intel sources failed for {ip_address}: {errors}")
                return {
                    'ip': ip_address,
                    'sources': [],
                    'errors': [{'source': src, 'error': err} for src, err in errors],
                    'partial_result': True,
                    'reputation_score': None,
                    'is_malicious': None,  # FIXED: Unknown, not False (could cause security bypass)
                    'is_unknown': True,  # Flag indicating TI data unavailable
                    'confidence': 0,
                    'last_checked': datetime.now().isoformat()
                }
            # Return consistent partial result when no sources and no errors
            return {
                'ip': ip_address,
                'sources': [],
                'partial_result': True,
                'reputation_score': None,
                'is_malicious': None,  # Unknown
                'is_unknown': True,
                'confidence': 0,
                'last_checked': datetime.now().isoformat()
            }

        # Aggregate results - include any errors that occurred
        merged = self._merge_threat_intel(ip_address, sources)
        if errors:
            merged['errors'] = [{'source': src, 'error': err} for src, err in errors]
            merged['partial_result'] = True
            self.logger.warning(f"Partial threat intel for {ip_address} - failed sources: {[e[0] for e in errors]}")
        return merged

    async def _query_virustotal(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API with error handling"""
        if not self.enable_error_handling:
            return await self._query_virustotal_impl(ip_address)

        try:
            return await self.vt_breaker.call_async(
                lambda: self.backoff.retry_async(self._query_virustotal_impl, ip_address)
            )
        except CircuitBreakerOpenException:
            self.logger.warning(f"VirusTotal circuit breaker open - skipping {ip_address}")
            return None
        except Exception as e:
            self.logger.error(f"VirusTotal query failed for {ip_address}: {e}")
            return None

    async def _query_virustotal_impl(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Internal VirusTotal API implementation with rate limiting and persistent caching"""
        # Check persistent cache first - avoids API call if cached
        cached_data = self.persistent_cache.get("virustotal", ip_address)
        if cached_data:
            self.logger.debug(f"VirusTotal CACHE HIT for {ip_address}")
            return cached_data

        # Wait for rate limiter before making request
        await self.vt_rate_limiter.acquire()

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.virustotal_api_key}

        try:
            async with aiohttp.ClientSession() as session:
                # Retry once if rate limited
                for attempt in range(2):
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        if response.status == 404:
                            return None
                        # Handle rate limiting (429) - wait and retry once
                        if response.status == 429:
                            if attempt == 0:
                                self.logger.warning(f"VirusTotal rate limit exceeded for {ip_address} - waiting 60s and retrying")
                                await asyncio.sleep(60)
                                continue  # Retry
                            else:
                                self.logger.error(f"VirusTotal rate limit still exceeded for {ip_address} after retry")
                                return None
                        # Handle authentication errors
                        if response.status in (401, 403):
                            self.logger.error(f"VirusTotal authentication error ({response.status}) - check API key")
                            return None
                        response.raise_for_status()
                        data = await response.json()
                        break  # Success, exit retry loop

                # Extract relevant data (safely handle None response) - outside retry loop
                data = data or {}
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})

                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                total = malicious + suspicious + harmless

                result = {
                    'source': 'VirusTotal',
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'reputation_score': max(0, 100 - (malicious + suspicious) * 10) if total > 0 else None,
                    'categories': attributes.get('categories', {}),
                    'last_analysis_date': attributes.get('last_analysis_date')
                }

                # Cache the result with intelligent TTL
                self.persistent_cache.set("virustotal", ip_address, result)
                self.logger.debug(f"VirusTotal API call for {ip_address} - cached result")

                return result

        except asyncio.TimeoutError:
            self.logger.warning(f"VirusTotal timeout for {ip_address} - skipping")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"VirusTotal network error for {ip_address}: {e}")
            return None

    async def _query_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API with error handling"""
        if not self.enable_error_handling:
            return await self._query_abuseipdb_impl(ip_address)

        try:
            return await self.abuse_breaker.call_async(
                lambda: self.backoff.retry_async(self._query_abuseipdb_impl, ip_address)
            )
        except CircuitBreakerOpenException:
            self.logger.warning(f"AbuseIPDB circuit breaker open - skipping {ip_address}")
            return None
        except Exception as e:
            self.logger.error(f"AbuseIPDB query failed for {ip_address}: {e}")
            return None

    async def _query_abuseipdb_impl(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Internal AbuseIPDB API implementation with rate limiting and persistent caching"""
        # Check persistent cache first - avoids API call if cached
        cached_data = self.persistent_cache.get("abuseipdb", ip_address)
        if cached_data:
            self.logger.debug(f"AbuseIPDB CACHE HIT for {ip_address}")
            return cached_data

        # Wait for rate limiter before making request
        await self.abuse_rate_limiter.acquire()

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.abuseipdb_api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": ""
        }

        try:
            async with aiohttp.ClientSession() as session:
                # Retry once if rate limited
                for attempt in range(2):
                    async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30)) as response:
                        # Handle rate limiting (429) - wait and retry once
                        if response.status == 429:
                            if attempt == 0:
                                self.logger.warning(f"AbuseIPDB rate limit exceeded for {ip_address} - waiting 60s and retrying")
                                await asyncio.sleep(60)
                                continue  # Retry
                            else:
                                self.logger.error(f"AbuseIPDB rate limit still exceeded for {ip_address} after retry")
                                return None
                        # Handle other client errors without retrying
                        if response.status in (401, 403):
                            self.logger.error(f"AbuseIPDB authentication error ({response.status}) - check API key")
                            return None
                        response.raise_for_status()
                        data = await response.json()
                        break  # Success, exit retry loop

                # Extract relevant data - outside retry loop
                api_result = data.get('data', {})

                result = {
                    'source': 'AbuseIPDB',
                    'abuse_confidence_score': api_result.get('abuseConfidenceScore', 0),
                    'total_reports': api_result.get('totalReports', 0),
                    'num_distinct_users': api_result.get('numDistinctUsers', 0),
                    'is_whitelisted': api_result.get('isWhitelisted', False),
                    'country_code': api_result.get('countryCode'),
                    'usage_type': api_result.get('usageType'),
                    'isp': api_result.get('isp')
                }

                # Cache the result with intelligent TTL
                self.persistent_cache.set("abuseipdb", ip_address, result)
                self.logger.debug(f"AbuseIPDB API call for {ip_address} - cached result")

                return result

        except asyncio.TimeoutError:
            self.logger.warning(f"AbuseIPDB timeout for {ip_address} - skipping")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"AbuseIPDB network error for {ip_address}: {e}")
            return None

    def _merge_threat_intel(self, ip_address: str, sources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge threat intelligence from multiple sources"""
        merged = {
            'ip': ip_address,
            'sources': [],
            'reputation_score': None,
            'is_malicious': False,
            'confidence': 0,
            'categories': [],
            'last_checked': datetime.now().isoformat()
        }

        total_score = 0
        score_count = 0

        # Collect data from all sources first
        abuse_data = {}
        sans_data = {}
        vt_data = {}

        for source_data in sources:
            source_name = source_data.get('source')
            merged['sources'].append(source_name)

            # Aggregate scores
            if source_name == 'VirusTotal':
                vt_data = source_data
                if source_data.get('reputation_score') is not None:
                    total_score += source_data['reputation_score']
                    score_count += 1

            elif source_name == 'AbuseIPDB':
                abuse_data = source_data
                abuse_score = source_data.get('abuse_confidence_score', 0)
                if abuse_score > 0:
                    total_score += (100 - abuse_score)
                    score_count += 1

            elif source_name == 'SANS_ISC':
                sans_data = source_data
                sans_score = source_data.get('threat_score', 0)
                if sans_score > 0:
                    total_score += (100 - sans_score)
                    score_count += 1

            # Merge additional data
            merged.update({
                f"{source_name.lower()}_data": source_data
            })

        # ============ TI-BASED MALICIOUS DETERMINATION ============
        # Avoids ML false positives by using concrete TI evidence
        #
        # Condition 1: AbuseIPDB confirms BAD
        #   - is_whitelisted = 0 AND abuse_confidence_score > 0 AND total_reports > 0
        #
        # Condition 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious
        #   - is_whitelisted = 1 AND SANS count > 0 AND SANS attacks > 0

        is_whitelisted = abuse_data.get('is_whitelisted', False)
        abuse_confidence = abuse_data.get('abuse_confidence_score', 0) or 0
        total_reports = abuse_data.get('total_reports', 0) or 0
        sans_count = sans_data.get('count', 0) or sans_data.get('attack_count', 0) or 0
        sans_attacks = sans_data.get('attacks', 0) or 0

        # Condition 1: AbuseIPDB confirms BAD (not whitelisted + confidence > 0 + reports > 0)
        if not is_whitelisted and abuse_confidence > 0 and total_reports > 0:
            merged['is_malicious'] = True
            merged['confidence'] = max(merged['confidence'], abuse_confidence)
            merged['malicious_reason'] = f"AbuseIPDB: confidence={abuse_confidence}%, reports={total_reports}"

        # Condition 2: Whitelisted by AbuseIPDB BUT SANS confirms malicious
        elif is_whitelisted and sans_count > 0 and sans_attacks > 0:
            merged['is_malicious'] = True
            merged['confidence'] = max(merged['confidence'], 75)
            merged['malicious_reason'] = f"SANS ISC: count={sans_count}, attacks={sans_attacks} (whitelisted by AbuseIPDB)"

        # Also mark as malicious if VirusTotal has significant detections (bonus check)
        elif vt_data.get('malicious_count', 0) >= 3:
            merged['is_malicious'] = True
            merged['confidence'] = max(merged['confidence'], 80)
            merged['malicious_reason'] = f"VirusTotal: {vt_data.get('malicious_count', 0)} malicious detections"

        # Calculate aggregate reputation score
        if score_count > 0:
            merged['reputation_score'] = int(total_score / score_count)

        # Set default confidence if not malicious
        if not merged['is_malicious']:
            merged['confidence'] = 50
            merged['malicious_reason'] = "Insufficient TI evidence"

        return merged

    def get_error_metrics(self) -> Dict[str, Any]:
        """Get error handling metrics"""
        if not self.enable_error_handling:
            return {"error_handling_enabled": False}

        return {
            "error_handling_enabled": True,
            "virustotal_circuit": self.vt_breaker.get_health(),
            "abuseipdb_circuit": self.abuse_breaker.get_health(),
            "dead_letter_queue": {
                "total_events": self.dlq.get_metrics().total_events,
                "pending_events": self.dlq.get_metrics().pending_events
            }
        }

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics for all threat intelligence sources.

        Returns:
            Dict with cache statistics including hit rates, cached IP counts, etc.
        """
        stats = {
            "persistent_cache": self.persistent_cache.get_stats(),
            "sans_isc_cache": {}
        }

        # Get SANS ISC cache stats if validator exists
        if self.sans_validator:
            try:
                sans_cache_dir = self.sans_validator.cache_dir
                sans_cached_count = len(list(sans_cache_dir.glob("*.json")))
                stats["sans_isc_cache"] = {
                    "cached_ips": sans_cached_count,
                    "cache_directory": str(sans_cache_dir)
                }
            except Exception as e:
                self.logger.debug(f"Could not get SANS ISC cache stats: {e}")

        return stats

    def cleanup_cache(self) -> Dict[str, int]:
        """
        Remove all expired cache entries from all sources.

        Returns:
            Dict with count of removed entries per source
        """
        removed = {
            "virustotal": 0,
            "abuseipdb": 0,
            "sans_isc": 0
        }

        # Cleanup persistent cache (VT + AbuseIPDB)
        total_removed = self.persistent_cache.cleanup_expired()
        # Note: persistent_cache handles both VT and AbuseIPDB together

        # SANS ISC cache cleanup
        if self.sans_validator:
            try:
                from datetime import timedelta
                sans_cache_dir = self.sans_validator.cache_dir
                sans_ttl_hours = getattr(self.sans_validator, 'CACHE_TTL_HOURS', 24)

                for cache_file in sans_cache_dir.glob("*.json"):
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            cache_entry = json.load(f)

                        cached_at = datetime.fromisoformat(cache_entry.get('timestamp', '2000-01-01'))
                        if datetime.now() > cached_at + timedelta(hours=sans_ttl_hours):
                            cache_file.unlink()
                            removed["sans_isc"] += 1
                    except (json.JSONDecodeError, IOError):
                        cache_file.unlink(missing_ok=True)
                        removed["sans_isc"] += 1
            except Exception as e:
                self.logger.warning(f"Error cleaning SANS ISC cache: {e}")

        self.logger.info(f"Cache cleanup completed: {total_removed} VT/AbuseIPDB, {removed['sans_isc']} SANS ISC entries removed")
        return removed

    def clear_cache(self) -> Dict[str, int]:
        """
        Clear all cached entries from all sources.

        Returns:
            Dict with count of cleared entries per source
        """
        cleared = {
            "persistent_cache": self.persistent_cache.clear_all(),
            "sans_isc": 0
        }

        # Clear SANS ISC cache
        if self.sans_validator:
            try:
                sans_cache_dir = self.sans_validator.cache_dir
                for cache_file in sans_cache_dir.glob("*.json"):
                    cache_file.unlink()
                    cleared["sans_isc"] += 1
            except Exception as e:
                self.logger.warning(f"Error clearing SANS ISC cache: {e}")

        self.logger.info(f"Cache cleared: {cleared['persistent_cache']} VT/AbuseIPDB, {cleared['sans_isc']} SANS ISC entries")
        return cleared
