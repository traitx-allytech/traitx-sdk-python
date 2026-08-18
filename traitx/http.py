"""HTTP transport built on the standard library.

No third-party dependencies: a fraud SDK that drags ``requests`` into every
service it touches causes more incidents than it prevents.

Timeouts, retry with full jitter, ``Retry-After`` and breaker integration.
See SPEC.md sections 9 and 10.
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Mapping, Optional

from .breaker import CircuitBreaker
from .config import Config, redact_key
from .decision import HttpOutcome

RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
RETRY_AFTER_CAP_MS = 5_000


@dataclass
class RequestSpec:
    method: str
    path: str
    query: Optional[Mapping[str, Optional[str]]] = None
    body: Optional[Any] = None
    headers: Dict[str, str] = field(default_factory=dict)
    #: Skip ``X-API-Key`` (management calls authenticate with a bearer token).
    omit_api_key: bool = False


class Transport:
    def __init__(self, config: Config, breaker: Optional[CircuitBreaker] = None) -> None:
        self._config = config
        self.breaker = breaker or CircuitBreaker(config.breaker)

    def send(self, spec: RequestSpec) -> HttpOutcome:
        """Perform a request. Never raises for transport or HTTP problems."""
        started = time.monotonic()

        if not self.breaker.allow_request():
            return HttpOutcome(status_code=0, latency_ms=0, transport_error="circuit breaker open")

        url = self._build_url(spec)
        headers = self._build_headers(spec)
        payload = None if spec.body is None else json.dumps(spec.body).encode("utf-8")
        timeout_s = self._config.timeout_ms / 1000.0

        last_error = "request failed"
        last_status = 0
        last_body: Optional[Dict[str, Any]] = None
        retry_after_ms: Optional[float] = None

        for attempt in range(self._config.max_retries + 1):
            if attempt > 0:
                time.sleep(
                    max(0.0, (retry_after_ms if retry_after_ms is not None else self._backoff_ms(attempt)) / 1000.0)
                )

            request = urllib.request.Request(url, data=payload, method=spec.method)
            for name, value in headers.items():
                request.add_header(name, value)

            try:
                self._debug(f"-> {spec.method} {url}")
                with urllib.request.urlopen(request, timeout=timeout_s) as response:
                    status = getattr(response, "status", response.getcode())
                    text = response.read().decode("utf-8", errors="replace")
                    retry_after_ms = _parse_retry_after(response.headers.get("Retry-After"))
                    last_status = status
                    last_body = _safe_json(text)
                    self._debug(f"<- {status} {spec.method} {url}", text[:2000])

                    if status in RETRYABLE_STATUSES and attempt < self._config.max_retries:
                        last_error = f"risk api returned HTTP {status}"
                        continue

                    self.breaker.record_success()
                    return HttpOutcome(
                        status_code=status,
                        body=last_body,
                        latency_ms=_elapsed_ms(started),
                    )

            except urllib.error.HTTPError as error:
                # urllib raises for >= 400; the body still matters.
                status = error.code
                text = ""
                try:
                    text = error.read().decode("utf-8", errors="replace")
                except Exception:  # pragma: no cover - body already consumed
                    pass
                retry_after_ms = _parse_retry_after(error.headers.get("Retry-After") if error.headers else None)
                last_status = status
                last_body = _safe_json(text)
                self._debug(f"<- {status} {spec.method} {url}", text[:2000])

                if status in RETRYABLE_STATUSES and attempt < self._config.max_retries:
                    last_error = f"risk api returned HTTP {status}"
                    continue

                if status >= 500 or status in (408, 429):
                    self.breaker.record_failure()
                else:
                    # A 401 is a settled answer from a healthy service; it must
                    # not count towards opening the breaker.
                    self.breaker.record_success()

                return HttpOutcome(
                    status_code=status,
                    body=last_body,
                    latency_ms=_elapsed_ms(started),
                )

            except Exception as error:  # noqa: BLE001 - urllib raises a wide range
                retry_after_ms = None
                last_error = _describe_transport_error(error, self._config.timeout_ms)
                self._debug(f"x {spec.method} {url}", last_error)
                if attempt >= self._config.max_retries:
                    break

        self.breaker.record_failure()
        return HttpOutcome(
            status_code=last_status if (last_status >= 500 or last_status == 429) else 0,
            body=last_body,
            latency_ms=_elapsed_ms(started),
            transport_error=last_error,
        )

    # -- internals ----------------------------------------------------------

    def _build_url(self, spec: RequestSpec) -> str:
        url = self._config.base_url + spec.path
        params = {k: v for k, v in (spec.query or {}).items() if v is not None}
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return url

    def _build_headers(self, spec: RequestSpec) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self._config.user_agent,
        }
        if spec.body is not None:
            headers["Content-Type"] = "application/json"
        if not spec.omit_api_key:
            headers["X-API-Key"] = self._config.api_key
        if self._config.application_id:
            headers["X-Application-ID"] = self._config.application_id
        headers.update(spec.headers)
        return headers

    def _backoff_ms(self, attempt: int) -> float:
        """Full jitter: ``random(0, base * 2^(n-1))``. SPEC.md section 9."""
        ceiling = self._config.retry_backoff_ms * (2 ** (attempt - 1))
        return random.uniform(0, ceiling)

    def _debug(self, message: str, detail: Any = None) -> None:
        if not self._config.debug:
            return
        self._config.logger.debug(
            "%s [key %s] %s", message, redact_key(self._config.api_key), detail if detail else ""
        )


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _safe_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        seconds = float(value)
        if seconds >= 0:
            return min(seconds * 1000, RETRY_AFTER_CAP_MS)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    import datetime as _dt

    now = _dt.datetime.now(when.tzinfo or _dt.timezone.utc)
    delta_ms = max(0.0, (when - now).total_seconds() * 1000)
    return min(delta_ms, RETRY_AFTER_CAP_MS)


def _describe_transport_error(error: Exception, timeout_ms: int) -> str:
    import socket

    if isinstance(error, socket.timeout):
        return f"risk api timed out after {timeout_ms}ms"
    if isinstance(error, urllib.error.URLError):
        reason = getattr(error, "reason", error)
        if isinstance(reason, socket.timeout):
            return f"risk api timed out after {timeout_ms}ms"
        return f"{type(error).__name__}: {reason}"
    if isinstance(error, TimeoutError):
        return f"risk api timed out after {timeout_ms}ms"
    return f"{type(error).__name__}: {error}"


__all__ = ["RequestSpec", "Transport"]
