"""Risk tiers with hysteresis (design.md §7).

| Tier | Entry | Exit |
|------|-------|------|
| 1 | p* < 1e-2 | 3 consecutive scorings with p* ≥ 1e-2 |
| 2 | p* < 1e-3 | 5 consecutive scorings with p* ≥ 1e-3 |
| 3 | p* < 1e-4 on 2 consecutive scorings | human release only |

The design states exits in windows; the fast path scores per action, so
"scorings" here are the agent's scored actions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    t1: float = 1e-2
    t2: float = 1e-3
    t3: float = 1e-4
    t3_consecutive: int = 2
    t1_exit_quiet: int = 3
    t2_exit_quiet: int = 5


@dataclass
class TierMachine:
    th: Thresholds = Thresholds()
    level: int = 0
    _t3_streak: int = 0
    _quiet: int = 0

    def update(self, p: float) -> int:
        th = self.th
        self._t3_streak = self._t3_streak + 1 if p < th.t3 else 0
        if self._t3_streak >= th.t3_consecutive:
            target = 3
        elif p < th.t2:
            target = 2
        elif p < th.t1:
            target = 1
        else:
            target = 0

        if self.level == 3:
            return 3  # human release only
        if target > self.level:
            self.level, self._quiet = target, 0
        elif target < self.level:
            self._quiet += 1
            needed = th.t2_exit_quiet if self.level == 2 else th.t1_exit_quiet
            if self._quiet >= needed:
                self.level, self._quiet = self.level - 1, 0
        else:
            self._quiet = 0
        return self.level
