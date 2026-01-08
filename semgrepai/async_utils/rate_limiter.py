"""Async rate limiter with exponential backoff for LLM API calls."""

import asyncio
import random
import logging
from dataclasses import dataclass, field
from typing import TypeVar, Callable, Awaitable, Optional
from functools import wraps

from aiolimiter import AsyncLimiter
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass


class MaxRetriesExceeded(Exception):
    """Raised when maximum retries are exceeded."""
    pass


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    max_concurrent: int = 4
    """Maximum number of concurrent requests."""

    requests_per_minute: int = 60
    """Maximum requests per minute."""

    max_retries: int = 3
    """Maximum number of retry attempts."""

    base_delay: float = 1.0
    """Base delay in seconds for exponential backoff."""

    max_delay: float = 60.0
    """Maximum delay in seconds for exponential backoff."""

    jitter: bool = True
    """Whether to add random jitter to delays."""


class AsyncRateLimiter:
    """
    Async rate limiter with semaphore-based concurrency control and token bucket rate limiting.

    Usage:
        limiter = AsyncRateLimiter(RateLimitConfig(max_concurrent=4, requests_per_minute=60))

        async def make_request():
            async with limiter:
                return await api_call()

        # Or with retry logic
        result = await limiter.execute_with_retry(api_call())
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._rate_limiter = AsyncLimiter(
            self.config.requests_per_minute,
            time_period=60
        )
        self._request_count = 0
        self._lock = asyncio.Lock()

    async def __aenter__(self):
        """Context manager entry - acquire semaphore and rate limit token."""
        await self._semaphore.acquire()
        await self._rate_limiter.acquire()
        async with self._lock:
            self._request_count += 1
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - release semaphore."""
        self._semaphore.release()
        return False

    @property
    def request_count(self) -> int:
        """Total number of requests made."""
        return self._request_count

    @property
    def available_slots(self) -> int:
        """Number of available concurrent slots."""
        return self._semaphore._value

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff delay with optional jitter."""
        delay = min(
            self.config.base_delay * (2 ** attempt),
            self.config.max_delay
        )
        if self.config.jitter:
            delay += random.uniform(0, delay * 0.1)
        return delay

    async def execute_with_retry(
        self,
        coro: Awaitable[T],
        retry_exceptions: tuple = (Exception,),
    ) -> T:
        """
        Execute a coroutine with rate limiting and retry logic.

        Args:
            coro: The coroutine to execute
            retry_exceptions: Tuple of exception types to retry on

        Returns:
            The result of the coroutine

        Raises:
            MaxRetriesExceeded: If all retry attempts fail
        """
        last_exception = None

        for attempt in range(self.config.max_retries):
            try:
                async with self:
                    return await coro
            except retry_exceptions as e:
                last_exception = e

                if attempt < self.config.max_retries - 1:
                    delay = self._calculate_backoff(attempt)
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{self.config.max_retries}): {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"Request failed after {self.config.max_retries} attempts: {e}"
                    )

        raise MaxRetriesExceeded(
            f"Failed after {self.config.max_retries} attempts"
        ) from last_exception


def with_rate_limit(
    limiter: AsyncRateLimiter,
    retry_exceptions: tuple = (Exception,),
):
    """
    Decorator to apply rate limiting and retry logic to an async function.

    Usage:
        limiter = AsyncRateLimiter()

        @with_rate_limit(limiter)
        async def my_api_call():
            return await external_api()
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            async def _call():
                return await func(*args, **kwargs)
            return await limiter.execute_with_retry(_call(), retry_exceptions)
        return wrapper
    return decorator


def create_llm_retry_decorator(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 60.0,
):
    """
    Create a tenacity retry decorator configured for LLM API calls.

    Handles common LLM API errors like rate limits, timeouts, and transient failures.

    Usage:
        @create_llm_retry_decorator()
        async def call_llm():
            return await llm.ainvoke(prompt)
    """
    return retry(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=min_wait, max=max_wait),
        retry=retry_if_exception_type((
            ConnectionError,
            TimeoutError,
            # Add provider-specific exceptions as needed
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
