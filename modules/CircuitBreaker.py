"""
Circuit Breaker Pattern Implementation
Prevents cascading failures by temporarily blocking calls to failing services

Features:
- Three states: CLOSED, OPEN, HALF_OPEN
- Configurable failure thresholds
- Automatic recovery testing
- Metrics and health monitoring
- Async and sync support
- Multiple failure detection strategies
"""

import time
import asyncio
import logging
from typing import Callable, Optional, Any, Dict
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque
import threading


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Blocking calls
    HALF_OPEN = "half_open"  # Testing recovery


class FailureDetectionStrategy(Enum):
    """Failure detection strategies"""
    THRESHOLD = "threshold"  # Failure count threshold
    RATE = "rate"  # Failure rate percentage
    CONSECUTIVE = "consecutive"  # Consecutive failures


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    # Failure detection
    failure_threshold: int = 5  # Number of failures before opening
    failure_rate_threshold: float = 0.5  # 50% failure rate
    consecutive_failures: int = 3
    detection_strategy: FailureDetectionStrategy = FailureDetectionStrategy.THRESHOLD

    # Timing
    timeout: float = 30.0  # Seconds before opening from half-open
    reset_timeout: float = 60.0  # Seconds to wait before half-open
    half_open_max_calls: int = 3  # Test calls in half-open state

    # Monitoring window
    window_size: int = 100  # Number of calls to track
    window_duration: int = 60  # Seconds for rate-based detection

    # Callbacks
    on_open: Optional[Callable] = None
    on_close: Optional[Callable] = None
    on_half_open: Optional[Callable] = None

    # Exceptions
    failure_exceptions: tuple = (Exception,)
    success_exceptions: tuple = ()  # Exceptions that count as success


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker"""
    state: CircuitState = CircuitState.CLOSED
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    state_changed_at: datetime = field(default_factory=datetime.now)
    time_in_open: float = 0.0
    time_in_half_open: float = 0.0


class CircuitBreakerOpenException(Exception):
    """Raised when circuit breaker is open"""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation

    States:
    - CLOSED: Normal operation, calls pass through
    - OPEN: Circuit is open, calls are rejected immediately
    - HALF_OPEN: Testing if service recovered, limited calls allowed

    Usage:
        breaker = CircuitBreaker(config)

        # Manual usage
        try:
            result = breaker.call(my_function, arg1, arg2)
        except CircuitBreakerOpenException:
            # Handle circuit open
            ...

        # Decorator usage
        @breaker.decorator()
        def my_function():
            ...
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.metrics = CircuitBreakerMetrics()
        self.logger = logging.getLogger(f"{__name__}.{name}")

        # Call history for windowed detection
        self.call_history: deque = deque(maxlen=self.config.window_size)
        self.timed_history: deque = deque()  # For time-based windows

        # State management
        self._state = CircuitState.CLOSED
        self._state_lock = threading.RLock()
        self._opened_at: Optional[float] = None
        self._half_open_calls: int = 0

    @property
    def state(self) -> CircuitState:
        """Get current state"""
        with self._state_lock:
            self._check_state_transition()
            return self._state

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenException: If circuit is open
        """
        with self._state_lock:
            self._check_state_transition()

            # Check if circuit is open
            if self._state == CircuitState.OPEN:
                self.metrics.rejected_calls += 1
                self.logger.warning(f"Circuit breaker {self.name} is OPEN - rejecting call")
                raise CircuitBreakerOpenException(
                    f"Circuit breaker {self.name} is open"
                )

            # Check half-open call limit
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self.metrics.rejected_calls += 1
                    raise CircuitBreakerOpenException(
                        f"Circuit breaker {self.name} is half-open - test limit reached"
                    )
                self._half_open_calls += 1

        # Execute function
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            self._record_success(time.time() - start_time)
            return result

        except self.config.success_exceptions as e:
            # These exceptions count as success
            self._record_success(time.time() - start_time)
            raise

        except self.config.failure_exceptions as e:
            self._record_failure(time.time() - start_time)
            raise

    async def call_async(self, func: Callable, *args, **kwargs) -> Any:
        """
        Async version of call

        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenException: If circuit is open
        """
        with self._state_lock:
            self._check_state_transition()

            # Check if circuit is open
            if self._state == CircuitState.OPEN:
                self.metrics.rejected_calls += 1
                self.logger.warning(f"Circuit breaker {self.name} is OPEN - rejecting call")
                raise CircuitBreakerOpenException(
                    f"Circuit breaker {self.name} is open"
                )

            # Check half-open call limit
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    self.metrics.rejected_calls += 1
                    raise CircuitBreakerOpenException(
                        f"Circuit breaker {self.name} is half-open - test limit reached"
                    )
                self._half_open_calls += 1

        # Execute function
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            self._record_success(time.time() - start_time)
            return result

        except self.config.success_exceptions as e:
            # These exceptions count as success
            self._record_success(time.time() - start_time)
            raise

        except self.config.failure_exceptions as e:
            self._record_failure(time.time() - start_time)
            raise

    def decorator(self):
        """
        Decorator for automatic circuit breaker protection

        Usage:
            @breaker.decorator()
            def my_function():
                ...
        """
        def decorator_wrapper(func):
            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, **kwargs):
                    return await self.call_async(func, *args, **kwargs)
                return async_wrapper
            else:
                @wraps(func)
                def sync_wrapper(*args, **kwargs):
                    return self.call(func, *args, **kwargs)
                return sync_wrapper

        return decorator_wrapper

    def _record_success(self, duration: float) -> None:
        """Record successful call"""
        with self._state_lock:
            self.metrics.total_calls += 1
            self.metrics.successful_calls += 1
            self.metrics.consecutive_successes += 1
            self.metrics.consecutive_failures = 0
            self.metrics.last_success_time = datetime.now()

            # Update history
            self.call_history.append(True)
            self.timed_history.append((time.time(), True))

            # State transitions
            if self._state == CircuitState.HALF_OPEN:
                # Successful test call
                if self.metrics.consecutive_successes >= self.config.half_open_max_calls:
                    self._transition_to_closed()
            elif self._state == CircuitState.CLOSED:
                # Reset consecutive failures on success
                pass

    def _record_failure(self, duration: float) -> None:
        """Record failed call"""
        with self._state_lock:
            self.metrics.total_calls += 1
            self.metrics.failed_calls += 1
            self.metrics.consecutive_failures += 1
            self.metrics.consecutive_successes = 0
            self.metrics.last_failure_time = datetime.now()

            # Update history
            self.call_history.append(False)
            self.timed_history.append((time.time(), False))

            # Check if should open circuit
            if self._should_open():
                self._transition_to_open()

    def _should_open(self) -> bool:
        """Check if circuit should open based on failure detection strategy"""
        strategy = self.config.detection_strategy

        if strategy == FailureDetectionStrategy.THRESHOLD:
            return self.metrics.failed_calls >= self.config.failure_threshold

        elif strategy == FailureDetectionStrategy.CONSECUTIVE:
            return self.metrics.consecutive_failures >= self.config.consecutive_failures

        elif strategy == FailureDetectionStrategy.RATE:
            # Calculate failure rate in recent calls
            if len(self.call_history) < 10:  # Need minimum sample
                return False

            failures = sum(1 for success in self.call_history if not success)
            failure_rate = failures / len(self.call_history)
            return failure_rate >= self.config.failure_rate_threshold

        return False

    def _check_state_transition(self) -> None:
        """Check if state should transition"""
        if self._state == CircuitState.OPEN:
            # Check if reset timeout has elapsed
            if self._opened_at:
                elapsed = time.time() - self._opened_at
                if elapsed >= self.config.reset_timeout:
                    self._transition_to_half_open()

    def _transition_to_open(self) -> None:
        """Transition to OPEN state"""
        if self._state == CircuitState.OPEN:
            return

        old_state = self._state
        self._state = CircuitState.OPEN
        self._opened_at = time.time()
        self._half_open_calls = 0
        self.metrics.state = CircuitState.OPEN
        self.metrics.state_changed_at = datetime.now()

        self.logger.error(
            f"Circuit breaker {self.name} opened. "
            f"Failures: {self.metrics.consecutive_failures}, "
            f"Rate: {self._get_failure_rate():.2%}"
        )

        if self.config.on_open:
            try:
                self.config.on_open()
            except Exception as e:
                self.logger.error(f"Error in on_open callback: {e}")

    def _transition_to_half_open(self) -> None:
        """Transition to HALF_OPEN state"""
        if self._state == CircuitState.HALF_OPEN:
            return

        old_state = self._state
        self._state = CircuitState.HALF_OPEN
        self._half_open_calls = 0
        self.metrics.state = CircuitState.HALF_OPEN
        self.metrics.state_changed_at = datetime.now()

        if self._opened_at:
            self.metrics.time_in_open += time.time() - self._opened_at

        self.logger.info(f"Circuit breaker {self.name} half-opened (testing recovery)")

        if self.config.on_half_open:
            try:
                self.config.on_half_open()
            except Exception as e:
                self.logger.error(f"Error in on_half_open callback: {e}")

    def _transition_to_closed(self) -> None:
        """Transition to CLOSED state"""
        if self._state == CircuitState.CLOSED:
            return

        old_state = self._state
        self._state = CircuitState.CLOSED
        self._opened_at = None
        self._half_open_calls = 0
        self.metrics.state = CircuitState.CLOSED
        self.metrics.state_changed_at = datetime.now()
        self.metrics.consecutive_failures = 0

        self.logger.info(f"Circuit breaker {self.name} closed (service recovered)")

        if self.config.on_close:
            try:
                self.config.on_close()
            except Exception as e:
                self.logger.error(f"Error in on_close callback: {e}")

    def _get_failure_rate(self) -> float:
        """Calculate current failure rate"""
        if not self.call_history:
            return 0.0

        failures = sum(1 for success in self.call_history if not success)
        return failures / len(self.call_history)

    def reset(self) -> None:
        """Manually reset circuit breaker to closed state"""
        with self._state_lock:
            self._transition_to_closed()
            self.call_history.clear()
            self.timed_history.clear()
            self.logger.info(f"Circuit breaker {self.name} manually reset")

    def force_open(self) -> None:
        """Manually force circuit breaker to open state"""
        with self._state_lock:
            self._transition_to_open()
            self.logger.warning(f"Circuit breaker {self.name} manually opened")

    def get_metrics(self) -> CircuitBreakerMetrics:
        """Get current metrics"""
        return self.metrics

    def get_health(self) -> Dict[str, Any]:
        """Get health status"""
        with self._state_lock:
            return {
                'name': self.name,
                'state': self._state.value,
                'healthy': self._state == CircuitState.CLOSED,
                'failure_rate': self._get_failure_rate(),
                'consecutive_failures': self.metrics.consecutive_failures,
                'total_calls': self.metrics.total_calls,
                'successful_calls': self.metrics.successful_calls,
                'failed_calls': self.metrics.failed_calls,
                'rejected_calls': self.metrics.rejected_calls,
                'last_failure': self.metrics.last_failure_time.isoformat() if self.metrics.last_failure_time else None,
                'last_success': self.metrics.last_success_time.isoformat() if self.metrics.last_success_time else None
            }


class CircuitBreakerRegistry:
    """
    Global registry for managing multiple circuit breakers

    Usage:
        registry = CircuitBreakerRegistry.get_instance()
        breaker = registry.get_or_create("elasticsearch", config)
    """

    _instance: Optional['CircuitBreakerRegistry'] = None
    _lock = threading.Lock()

    def __init__(self):
        self.breakers: Dict[str, CircuitBreaker] = {}
        self.logger = logging.getLogger(__name__)

    @classmethod
    def get_instance(cls) -> 'CircuitBreakerRegistry':
        """Get singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get existing or create new circuit breaker"""
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(name, config)
            self.logger.info(f"Created circuit breaker: {name}")

        return self.breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self.breakers.get(name)

    def remove(self, name: str) -> None:
        """Remove circuit breaker"""
        if name in self.breakers:
            del self.breakers[name]
            self.logger.info(f"Removed circuit breaker: {name}")

    def get_all_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health status of all circuit breakers"""
        return {
            name: breaker.get_health()
            for name, breaker in self.breakers.items()
        }

    def reset_all(self) -> None:
        """Reset all circuit breakers"""
        for breaker in self.breakers.values():
            breaker.reset()
        self.logger.info("Reset all circuit breakers")
