"""Circuit breaker — SPEC.md section 10.

Counts transport failures only. Its whole purpose is that one unreachable
dependency costs you one timeout, not a timeout on every login.
"""

from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Callable

from .config import BreakerOptions


class BreakerState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Thread-safe: a WSGI app serves requests from a pool of threads."""

    def __init__(
        self,
        options: BreakerOptions,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._options = options
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> BreakerState:
        if self._failures < self._options.failure_threshold:
            return BreakerState.CLOSED
        elapsed_ms = (self._clock() - self._opened_at) * 1000
        if elapsed_ms >= self._options.reset_after_ms:
            return BreakerState.HALF_OPEN
        return BreakerState.OPEN

    def allow_request(self) -> bool:
        """True when the call may touch the network.

        In half-open exactly one probe is admitted; concurrent callers are
        short-circuited until it settles.
        """
        with self._lock:
            state = self._state_locked()
            if state == BreakerState.CLOSED:
                return True
            if state == BreakerState.OPEN:
                return False
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = 0.0
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._failures += 1
            if self._failures >= self._options.failure_threshold:
                self._opened_at = self._clock()

    def reset(self) -> None:
        self.record_success()


__all__ = ["BreakerState", "CircuitBreaker"]
