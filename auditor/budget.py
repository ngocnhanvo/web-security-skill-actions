"""Hard request budget and fail-fast stop conditions."""
from __future__ import annotations
from dataclasses import dataclass, field
import time
from collections.abc import Callable


class BudgetError(Exception):
    pass


@dataclass
class Budget:
    max_requests: int = 30
    min_interval_seconds: float = 1.0
    now: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    used: int = field(default=0, init=False)
    last_request: float | None = field(default=None, init=False)
    stopped: bool = field(default=False, init=False)

    def __post_init__(self):
        if not 1 <= self.max_requests <= 30 or not 0 <= self.min_interval_seconds:
            raise BudgetError('Invalid safety budget')

    def before(self) -> None:
        if self.stopped or self.used >= self.max_requests:
            raise BudgetError('Request budget exhausted or stopped')
        if self.last_request is not None:
            delay = self.min_interval_seconds - (self.now() - self.last_request)
            if delay > 0:
                self.sleep(delay)
        self.used += 1
        self.last_request = self.now()

    def after(self, status: int) -> None:
        if status == 429 or status >= 500:
            self.stopped = True
            raise BudgetError('Target appears rate-limited or unhealthy; aborting scan')
