"""
Exponential Backoff Retry Mechanism
Implements intelligent retry logic with exponential backoff and jitter

Features:
- Configurable retry strategies
- Exponential backoff with jitter
- Custom exception handling
- Retry budgets and rate limiting
- Async and sync support
- Detailed retry metrics
"""

import time
import asyncio
import random
import logging
from typing import Callable, Optional, Type, Tuple, Any, Union, List
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class BackoffStrategy(Enum):
    """Backoff calculation strategies"""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    FIBONACCI = "fibonacci"
    CONSTANT = "constant"


@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_attempts: int = 5
    initial_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_factor: float = 0.1  # 10% jitter
    strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL

    # Exception handling
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    fatal_exceptions: Tuple[Type[Exception], ...] = ()

    # Rate limiting
    max_retries_per_minute: Optional[int] = None
    retry_budget_window: int = 60  # seconds

    # Callbacks
    on_retry: Optional[Callable] = None
    on_success: Optional[Callable] = None
    on_failure: Optional[Callable] = None


@dataclass
class RetryMetrics:
    """Metrics for retry operations"""
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    total_delay: float = 0.0
    last_attempt: Optional[datetime] = None
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    exception_counts: dict = field(default_factory=dict)


class RetryBudget:
    """
    Manages retry budget to prevent retry storms
    Implements token bucket algorithm
    """

    def __init__(self, max_retries_per_window: int, window_seconds: int = 60):
        self.max_retries = max_retries_per_window
        self.window_seconds = window_seconds
        self.retry_times: List[datetime] = []
        self.logger = logging.getLogger(__name__)

    def can_retry(self) -> bool:
        """Check if retry is allowed within budget"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Remove old entries
        self.retry_times = [t for t in self.retry_times if t > cutoff]

        # Check budget
        if len(self.retry_times) >= self.max_retries:
            self.logger.warning(
                f"Retry budget exceeded: {len(self.retry_times)} retries in last {self.window_seconds}s"
            )
            return False

        return True

    def record_retry(self) -> None:
        """Record a retry attempt"""
        self.retry_times.append(datetime.now())

    def reset(self) -> None:
        """Reset retry budget"""
        self.retry_times.clear()


class ExponentialBackoff:
    """
    Exponential backoff retry mechanism

    Usage:
        backoff = ExponentialBackoff(config)
        result = backoff.retry(my_function, arg1, arg2, kwarg1=value1)

        # Or use as decorator
        @backoff.decorator()
        def my_function():
            ...
    """

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self.metrics = RetryMetrics()
        self.logger = logging.getLogger(__name__)

        # Initialize retry budget if configured
        self.retry_budget = None
        if self.config.max_retries_per_minute:
            self.retry_budget = RetryBudget(
                self.config.max_retries_per_minute,
                self.config.retry_budget_window
            )

    def retry(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry logic

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Last exception if all retries exhausted
        """
        last_exception = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Check retry budget
                if self.retry_budget and attempt > 1:
                    if not self.retry_budget.can_retry():
                        self.logger.error("Retry budget exhausted")
                        raise Exception("Retry budget exhausted")
                    self.retry_budget.record_retry()

                # Execute function
                self.logger.debug(f"Attempt {attempt}/{self.config.max_attempts}")
                result = func(*args, **kwargs)

                # Success
                self.metrics.total_attempts += 1
                self.metrics.successful_attempts += 1
                self.metrics.last_attempt = datetime.now()
                self.metrics.last_success = datetime.now()

                if self.config.on_success:
                    self.config.on_success(attempt, result)

                return result

            except self.config.fatal_exceptions as e:
                # Fatal exception - don't retry
                self.logger.error(f"Fatal exception: {type(e).__name__}: {e}")
                self.metrics.failed_attempts += 1
                raise

            except self.config.retry_on_exceptions as e:
                last_exception = e
                self.metrics.total_attempts += 1
                self.metrics.last_attempt = datetime.now()

                # Track exception types
                exc_type = type(e).__name__
                self.metrics.exception_counts[exc_type] = \
                    self.metrics.exception_counts.get(exc_type, 0) + 1

                # Check if we should retry
                if attempt >= self.config.max_attempts:
                    self.logger.error(
                        f"All retry attempts exhausted. Last error: {type(e).__name__}: {e}"
                    )
                    self.metrics.failed_attempts += 1
                    self.metrics.last_failure = datetime.now()

                    if self.config.on_failure:
                        self.config.on_failure(attempt, e)

                    raise

                # Calculate delay
                delay = self._calculate_delay(attempt)
                self.metrics.total_delay += delay

                self.logger.warning(
                    f"Attempt {attempt} failed: {type(e).__name__}: {e}. "
                    f"Retrying in {delay:.2f}s..."
                )

                # Call retry callback
                if self.config.on_retry:
                    self.config.on_retry(attempt, e, delay)

                # Sleep before retry
                time.sleep(delay)

        # Should never reach here, but just in case
        if last_exception:
            raise last_exception

    async def retry_async(self, func: Callable, *args, **kwargs) -> Any:
        """
        Async version of retry

        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Last exception if all retries exhausted
        """
        last_exception = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Check retry budget
                if self.retry_budget and attempt > 1:
                    if not self.retry_budget.can_retry():
                        self.logger.error("Retry budget exhausted")
                        raise Exception("Retry budget exhausted")
                    self.retry_budget.record_retry()

                # Execute function
                self.logger.debug(f"Attempt {attempt}/{self.config.max_attempts}")
                result = await func(*args, **kwargs)

                # Success
                self.metrics.total_attempts += 1
                self.metrics.successful_attempts += 1
                self.metrics.last_attempt = datetime.now()
                self.metrics.last_success = datetime.now()

                if self.config.on_success:
                    if asyncio.iscoroutinefunction(self.config.on_success):
                        await self.config.on_success(attempt, result)
                    else:
                        self.config.on_success(attempt, result)

                return result

            except self.config.fatal_exceptions as e:
                # Fatal exception - don't retry
                self.logger.error(f"Fatal exception: {type(e).__name__}: {e}")
                self.metrics.failed_attempts += 1
                raise

            except self.config.retry_on_exceptions as e:
                last_exception = e
                self.metrics.total_attempts += 1
                self.metrics.last_attempt = datetime.now()

                # Track exception types
                exc_type = type(e).__name__
                self.metrics.exception_counts[exc_type] = \
                    self.metrics.exception_counts.get(exc_type, 0) + 1

                # Check if we should retry
                if attempt >= self.config.max_attempts:
                    self.logger.error(
                        f"All retry attempts exhausted. Last error: {type(e).__name__}: {e}"
                    )
                    self.metrics.failed_attempts += 1
                    self.metrics.last_failure = datetime.now()

                    if self.config.on_failure:
                        if asyncio.iscoroutinefunction(self.config.on_failure):
                            await self.config.on_failure(attempt, e)
                        else:
                            self.config.on_failure(attempt, e)

                    raise

                # Calculate delay
                delay = self._calculate_delay(attempt)
                self.metrics.total_delay += delay

                self.logger.warning(
                    f"Attempt {attempt} failed: {type(e).__name__}: {e}. "
                    f"Retrying in {delay:.2f}s..."
                )

                # Call retry callback
                if self.config.on_retry:
                    if asyncio.iscoroutinefunction(self.config.on_retry):
                        await self.config.on_retry(attempt, e, delay)
                    else:
                        self.config.on_retry(attempt, e, delay)

                # Sleep before retry
                await asyncio.sleep(delay)

        # Should never reach here, but just in case
        if last_exception:
            raise last_exception

    def decorator(self, **config_overrides):
        """
        Decorator for automatic retry

        Usage:
            @backoff.decorator(max_attempts=3)
            def my_function():
                ...
        """
        def decorator_wrapper(func):
            # Merge config overrides
            config = RetryConfig(
                **{**self.config.__dict__, **config_overrides}
            )
            backoff = ExponentialBackoff(config)

            if asyncio.iscoroutinefunction(func):
                @wraps(func)
                async def async_wrapper(*args, **kwargs):
                    return await backoff.retry_async(func, *args, **kwargs)
                return async_wrapper
            else:
                @wraps(func)
                def sync_wrapper(*args, **kwargs):
                    return backoff.retry(func, *args, **kwargs)
                return sync_wrapper

        return decorator_wrapper

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt"""
        if self.config.strategy == BackoffStrategy.EXPONENTIAL:
            delay = self.config.initial_delay * (self.config.exponential_base ** (attempt - 1))
        elif self.config.strategy == BackoffStrategy.LINEAR:
            delay = self.config.initial_delay * attempt
        elif self.config.strategy == BackoffStrategy.FIBONACCI:
            delay = self.config.initial_delay * self._fibonacci(attempt)
        else:  # CONSTANT
            delay = self.config.initial_delay

        # Cap at max delay
        delay = min(delay, self.config.max_delay)

        # Add jitter
        if self.config.jitter:
            jitter_amount = delay * self.config.jitter_factor
            delay += random.uniform(-jitter_amount, jitter_amount)

        return max(0, delay)  # Ensure non-negative

    def _fibonacci(self, n: int) -> int:
        """Calculate nth Fibonacci number"""
        if n <= 1:
            return n
        a, b = 0, 1
        for _ in range(2, n + 1):
            a, b = b, a + b
        return b

    def get_metrics(self) -> RetryMetrics:
        """Get retry metrics"""
        return self.metrics

    def reset_metrics(self) -> None:
        """Reset metrics"""
        self.metrics = RetryMetrics()

    def reset_budget(self) -> None:
        """Reset retry budget"""
        if self.retry_budget:
            self.retry_budget.reset()


# Convenience decorators

def retry(
    max_attempts: int = 5,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
    fatal_on: Tuple[Type[Exception], ...] = ()
):
    """
    Convenience decorator for retry logic

    Usage:
        @retry(max_attempts=3, initial_delay=2.0)
        def my_function():
            ...
    """
    config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
        retry_on_exceptions=retry_on,
        fatal_exceptions=fatal_on
    )
    backoff = ExponentialBackoff(config)
    return backoff.decorator()


def retry_async(
    max_attempts: int = 5,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retry_on: Tuple[Type[Exception], ...] = (Exception,),
    fatal_on: Tuple[Type[Exception], ...] = ()
):
    """
    Convenience decorator for async retry logic

    Usage:
        @retry_async(max_attempts=3, initial_delay=2.0)
        async def my_function():
            ...
    """
    return retry(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
        retry_on=retry_on,
        fatal_on=fatal_on
    )
