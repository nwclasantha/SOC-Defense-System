import logging
import json
import aiohttp
import ssl
from typing import List, Dict, Any, Optional

# Module imports
from modules.DataSource import DataSource
from modules.CLIConfiguration import CLIConfiguration
from modules.ExponentialBackoff import RetryConfig, ExponentialBackoff, BackoffStrategy
from modules.CircuitBreaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenException, CircuitBreakerRegistry
from modules.DeadLetterQueue import DeadLetterQueue, DLQEventPriority

class ElasticsearchDataSource(DataSource):
    """
    Enhanced Elasticsearch data source with comprehensive error handling

    Features:
    - Exponential backoff with jitter for transient failures
    - Circuit breaker to prevent cascading failures
    - Dead letter queue for failed queries
    - Automatic retry with smart failure detection
    """

    def __init__(self, config: CLIConfiguration, enable_error_handling: bool = True):
        self.config = config
        self.session = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.enable_error_handling = enable_error_handling

        # Initialize error handling components
        if enable_error_handling:
            self._init_error_handling()

    def _init_error_handling(self) -> None:
        """Initialize error handling components"""
        # Exponential backoff configuration
        self.retry_config = RetryConfig(
            max_attempts=5,
            initial_delay=1.0,
            max_delay=30.0,
            exponential_base=2.0,
            jitter=True,
            strategy=BackoffStrategy.EXPONENTIAL,
            retry_on_exceptions=(
                aiohttp.ClientError,
                aiohttp.ServerTimeoutError,
                aiohttp.ServerConnectionError,
                ConnectionError,
                TimeoutError
            ),
            fatal_exceptions=(
                aiohttp.ClientResponseError,  # 4xx errors are fatal
            ),
            max_retries_per_minute=30  # Rate limiting
        )
        self.backoff = ExponentialBackoff(self.retry_config)

        # Circuit breaker configuration
        breaker_config = CircuitBreakerConfig(
            failure_threshold=5,
            failure_rate_threshold=0.5,
            reset_timeout=60.0,
            half_open_max_calls=3,
            timeout=30.0,
            failure_exceptions=(
                aiohttp.ClientError,
                aiohttp.ServerTimeoutError,
                ConnectionError,
                TimeoutError
            ),
            on_open=self._on_circuit_open,
            on_close=self._on_circuit_close
        )

        # Get or create circuit breaker from registry
        registry = CircuitBreakerRegistry.get_instance()
        self.circuit_breaker = registry.get_or_create("elasticsearch", breaker_config)

        # Dead letter queue
        self.dlq = DeadLetterQueue(
            db_path="dlq/elasticsearch_dlq.db",
            auto_process=False
        )

        self.logger.info("Error handling initialized for Elasticsearch data source")

    def _on_circuit_open(self) -> None:
        """Callback when circuit breaker opens"""
        self.logger.critical("Elasticsearch circuit breaker OPENED - queries will be rejected")

    def _on_circuit_close(self) -> None:
        """Callback when circuit breaker closes"""
        self.logger.info("Elasticsearch circuit breaker CLOSED - service recovered")

    async def __aenter__(self):
        """Async context manager entry."""
        # Create SSL context
        if self.config.verify_ssl:
            ssl_context = True  # Use default SSL verification
        else:
            # Disable SSL verification (for self-signed certificates)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        # Create connector with improved DNS and connection settings
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
            use_dns_cache=True,
            keepalive_timeout=30,
            limit=10,  # Max connections
            enable_cleanup_closed=True
        )

        # Create session with longer timeouts for DNS issues
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=30,  # 30 seconds for connection (includes DNS)
            sock_connect=30,
            sock_read=60
        )

        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def warmup_dns(self) -> bool:
        """Pre-resolve DNS to warm up cache and detect connectivity issues early"""
        import socket
        import asyncio
        import concurrent.futures

        try:
            # Extract hostname from URL
            from urllib.parse import urlparse
            parsed = urlparse(self.config.elasticsearch_url)
            hostname = parsed.hostname
            port = parsed.port or 9200

            self.logger.info(f"Warming up DNS for {hostname}...")

            # Run DNS lookup in thread pool with timeout to avoid blocking event loop
            def resolve_dns():
                return socket.getaddrinfo(hostname, port, socket.AF_INET)

            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                try:
                    # 10 second timeout for DNS resolution
                    addresses = await asyncio.wait_for(
                        loop.run_in_executor(executor, resolve_dns),
                        timeout=10.0
                    )
                    if addresses:
                        ip = addresses[0][4][0]
                        self.logger.info(f"DNS resolved: {hostname} -> {ip}")
                        return True
                except asyncio.TimeoutError:
                    self.logger.warning(f"DNS warmup timed out for {hostname} (10s)")
                    return False

        except socket.gaierror as e:
            self.logger.warning(f"DNS warmup failed for {hostname}: {e}")
        except Exception as e:
            self.logger.warning(f"DNS warmup error: {e}")
        return False

    async def query_alerts(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Query alerts from Elasticsearch with comprehensive error handling

        Features:
        - Automatic retry with exponential backoff
        - Circuit breaker protection
        - Dead letter queue for failed queries
        - Pagination support with scroll API
        """
        if not self.enable_error_handling:
            # Use original implementation without error handling
            return await self._query_alerts_impl(query)

        # Wrap query in circuit breaker and retry logic
        try:
            return await self.circuit_breaker.call_async(
                lambda: self.backoff.retry_async(self._query_alerts_impl, query)
            )
        except CircuitBreakerOpenException as e:
            self.logger.error(f"Circuit breaker open - query rejected: {e}")
            # Add to DLQ for later processing
            self.dlq.add_event(
                event_type="elasticsearch_query",
                payload={"query": query},
                error=e,
                source="ElasticsearchDataSource",
                priority=DLQEventPriority.HIGH,
                max_retries=10,
                ttl_hours=48
            )
            raise
        except Exception as e:
            self.logger.error(f"Query failed after all retries: {e}")
            # Add to DLQ for later processing
            self.dlq.add_event(
                event_type="elasticsearch_query",
                payload={"query": query},
                error=e,
                source="ElasticsearchDataSource",
                priority=DLQEventPriority.HIGH,
                max_retries=10,
                ttl_hours=48
            )
            raise

    async def _query_alerts_impl(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Internal implementation of query_alerts"""
        alerts = []
        scroll_id = None

        try:
            # Initial search request
            url = f"{self.config.elasticsearch_url}/wazuh-alerts-*/_search?scroll=1m"
            headers = {"Content-Type": "application/json"}
            auth = aiohttp.BasicAuth(self.config.elasticsearch_user, self.config.elasticsearch_password)

            self.logger.info(f"Querying Elasticsearch: {url}")
            self.logger.debug(f"Query: {json.dumps(query, indent=2)}")

            async with self.session.post(url, json=query, headers=headers, auth=auth) as response:
                self.logger.info(f"Response status: {response.status}")
                response.raise_for_status()
                data = await response.json()

                # Safely access nested response structure
                hits_data = data.get('hits', {})
                total_data = hits_data.get('total', {})
                total = total_data.get('value', 0) if isinstance(total_data, dict) else total_data
                scroll_id = data.get('_scroll_id')
                hits = hits_data.get('hits', [])
                alerts.extend(hits)

                self.logger.info(f"Initial query returned {len(hits)} hits (total: {total})")

                if total == 0:
                    self.logger.debug(f"No results found for current time window")

                # Handle pagination with scroll
                # CRITICAL FIX: If max_results_per_query is set to -1, fetch ALL results without limit
                max_results = self.config.max_results_per_query if self.config.max_results_per_query > 0 else float('inf')
                while len(hits) > 0 and len(alerts) < max_results:
                    scroll_url = f"{self.config.elasticsearch_url}/_search/scroll"
                    scroll_query = {"scroll": "1m", "scroll_id": scroll_id}

                    async with self.session.post(scroll_url, json=scroll_query, headers=headers, auth=auth) as scroll_response:
                        scroll_response.raise_for_status()
                        scroll_data = await scroll_response.json()

                        scroll_hits_data = scroll_data.get('hits', {})
                        hits = scroll_hits_data.get('hits', [])
                        alerts.extend(hits)
                        self.logger.debug(f"Scroll returned {len(hits)} more hits")

                self.logger.info(f"Retrieved {len(alerts)} alerts from Elasticsearch")

        except Exception as e:
            self.logger.error(f"Error querying Elasticsearch: {type(e).__name__}: {e}")
            raise

        finally:
            # Clean up scroll context
            if scroll_id:
                try:
                    auth = aiohttp.BasicAuth(self.config.elasticsearch_user, self.config.elasticsearch_password)
                    clear_url = f"{self.config.elasticsearch_url}/_search/scroll"
                    await self.session.delete(clear_url, json={"scroll_id": scroll_id}, auth=auth)
                except (aiohttp.ClientError, asyncio.TimeoutError, Exception) as e:
                    self.logger.debug(f"Scroll cleanup failed (non-fatal): {e}")

        return alerts

    async def health_check(self) -> bool:
        """
        Check Elasticsearch connectivity with retry logic

        Returns:
            True if Elasticsearch is healthy, False otherwise
        """
        import asyncio

        self.logger.info("Starting Elasticsearch health check...")

        if not self.enable_error_handling:
            try:
                # Add 30 second timeout to health check
                return await asyncio.wait_for(self._health_check_impl(), timeout=30.0)
            except asyncio.TimeoutError:
                self.logger.error("Health check timed out after 30 seconds")
                return False

        try:
            # Use retry but not circuit breaker for health checks
            # Add overall timeout of 60 seconds for all retries
            return await asyncio.wait_for(
                self.backoff.retry_async(self._health_check_impl),
                timeout=60.0
            )
        except asyncio.TimeoutError:
            self.logger.error("Health check timed out after 60 seconds (including retries)")
            return False
        except Exception as e:
            self.logger.error(f"Health check failed after all retries: {e}")
            return False

    async def _health_check_impl(self) -> bool:
        """Internal implementation of health_check"""
        try:
            url = f"{self.config.elasticsearch_url}/_cluster/health"
            auth = aiohttp.BasicAuth(self.config.elasticsearch_user, self.config.elasticsearch_password)

            self.logger.debug(f"Checking cluster health at: {url}")
            async with self.session.get(url, auth=auth) as response:
                response.raise_for_status()
                data = await response.json()
                status = data.get('status')

                self.logger.info(f"Elasticsearch cluster status: {status}")
                return status in ['green', 'yellow']

        except Exception as e:
            self.logger.error(f"Elasticsearch health check failed: {type(e).__name__}: {e}")
            raise  # Re-raise to trigger retry logic

    def get_error_metrics(self) -> Dict[str, Any]:
        """
        Get error handling metrics

        Returns:
            Dictionary with retry, circuit breaker, and DLQ metrics
        """
        if not self.enable_error_handling:
            return {"error_handling_enabled": False}

        retry_metrics = self.backoff.get_metrics()
        circuit_metrics = self.circuit_breaker.get_metrics()
        dlq_metrics = self.dlq.get_metrics()

        return {
            "error_handling_enabled": True,
            "retry": {
                "total_attempts": retry_metrics.total_attempts,
                "successful_attempts": retry_metrics.successful_attempts,
                "failed_attempts": retry_metrics.failed_attempts,
                "total_delay": retry_metrics.total_delay,
                "last_success": retry_metrics.last_success.isoformat() if retry_metrics.last_success else None,
                "last_failure": retry_metrics.last_failure.isoformat() if retry_metrics.last_failure else None
            },
            "circuit_breaker": {
                "state": circuit_metrics.state.value,
                "total_calls": circuit_metrics.total_calls,
                "successful_calls": circuit_metrics.successful_calls,
                "failed_calls": circuit_metrics.failed_calls,
                "rejected_calls": circuit_metrics.rejected_calls,
                "consecutive_failures": circuit_metrics.consecutive_failures
            },
            "dead_letter_queue": {
                "total_events": dlq_metrics.total_events,
                "pending_events": dlq_metrics.pending_events,
                "failed_events": dlq_metrics.failed_events,
                "recovered_events": dlq_metrics.recovered_events,
                "poison_messages": dlq_metrics.poison_messages
            }
        }

    def reset_error_handling(self) -> None:
        """Reset error handling state (useful for testing or recovery)"""
        if not self.enable_error_handling:
            return

        self.backoff.reset_metrics()
        self.backoff.reset_budget()
        self.circuit_breaker.reset()
        self.logger.info("Error handling state reset")

    def get_dlq_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get failed events from dead letter queue

        Args:
            limit: Maximum number of events to return

        Returns:
            List of DLQ events
        """
        if not self.enable_error_handling:
            return []

        events = self.dlq.get_pending_events(limit=limit)
        return [event.to_dict() for event in events]
