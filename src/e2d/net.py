"""HTTP retry envelope shared by outbound calls.

The defaults are copied from the OpenTelemetry Collector's exporterhelper,
which has had years of production tuning: 5 s initial backoff growing x1.5 to
a 30 s cap, giving up after 300 s elapsed. Throttles and server faults (429,
5xx, timeouts, connection errors) retry, honoring ``Retry-After`` when the
server sends one. Other 4xx fail immediately: a payload the server has
rejected as malformed can never succeed, and retrying it only burns time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


@dataclass
class RetryPolicy:
    initial: float = 5.0
    multiplier: float = 1.5
    max_interval: float = 30.0
    max_elapsed: float = 300.0


# an attempt reports: (ok, retryable, detail, retry_after_seconds_or_None)
Attempt = Callable[[], Tuple[bool, bool, str, Optional[float]]]


def with_retry(attempt: Attempt, policy: Optional[RetryPolicy] = None,
               sleep=time.sleep, clock=time.monotonic) -> Tuple[bool, str, int]:
    """Run `attempt` under the envelope. Returns (ok, detail, retries_used)."""
    policy = policy or RetryPolicy()
    start = clock()
    interval = policy.initial
    retries = 0
    while True:
        ok, retryable, detail, retry_after = attempt()
        if ok or not retryable:
            return ok, detail, retries
        elapsed = clock() - start
        if elapsed >= policy.max_elapsed:
            return False, f"gave up after {elapsed:.0f}s / {retries} retries: {detail}", retries
        delay = retry_after if retry_after else min(interval, policy.max_interval)
        sleep(max(0.0, delay))
        interval *= policy.multiplier
        retries += 1


def classify_response(status: int, text: str, headers=None) -> Tuple[bool, bool, str, Optional[float]]:
    """Fold an HTTP response into the attempt tuple."""
    if status < 400:
        return True, False, "", None
    retry_after = None
    if headers:
        raw = headers.get("Retry-After")
        if raw:
            try:
                retry_after = float(raw)
            except (TypeError, ValueError):
                pass
    detail = f"HTTP {status}: {text[:200]}"
    return False, status in RETRYABLE_STATUS, detail, retry_after
