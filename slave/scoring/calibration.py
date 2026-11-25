"""Conformal calibration and fusion (design.md §7).

A detector's raw score is turned into a p-value against a held-out set of
benign scores from the same stratum (here: the agent's role):

    p = (1 + #{calibration scores ≥ s}) / (n + 1)

Under benign traffic p is (super-)uniform, so thresholding at α gives a false
alert rate of at most α per scored event. Detectors are correlated, so they are
fused with a Bonferroni-adjusted minimum, valid under any dependence:

    p* = min(1, m · min_d p_d)
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ConformalCalibrator:
    scores: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    _frozen: bool = False

    def add(self, stratum: str, score: float) -> None:
        assert not self._frozen, "calibrator is frozen"
        self.scores[stratum].append(score)

    def freeze(self) -> ConformalCalibrator:
        for xs in self.scores.values():
            xs.sort()
        self.scores = dict(self.scores)
        self._frozen = True
        return self

    def n(self, stratum: str) -> int:
        return len(self.scores.get(stratum, ()))

    def p_value(self, stratum: str, score: float) -> float:
        xs = self.scores.get(stratum)
        if not xs:
            return 1.0  # no calibration data for this stratum → never alert on it
        ge = len(xs) - bisect.bisect_left(xs, score)
        return (1 + ge) / (len(xs) + 1)


def fuse(p_values: list[float]) -> float:
    return min(1.0, len(p_values) * min(p_values))
