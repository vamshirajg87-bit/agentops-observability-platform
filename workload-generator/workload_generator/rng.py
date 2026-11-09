"""
workload_generator/rng.py

Seeded draws for the planner.

Every draw stream is derived from the master seed, a namespace and an index
through SHA-256, so the stream for request N depends on nothing but those
three values: not on how many requests are planned around it, not on the
order they are later executed in, and not on Python's per-process hash
randomization.

Only random.Random.random() is used as the source of randomness.  Its output
for a given seed is stable across Python versions; the distribution helpers
of the random module are not promised to be, so the few distributions needed
here are written out.

Standard library only.

Public API:
    derive_hex()   a stable hexadecimal digest of the given parts
    Draw           one seeded stream with the distributions the planner uses
"""

from __future__ import annotations

import hashlib
import math
import random
from typing import Sequence, TypeVar

T = TypeVar("T")

#: Changing this string changes every plan; it is the version of the
#: derivation, not of the package.
_DERIVATION: str = "agentops-workload-plan/1"


def derive_hex(*parts: object) -> str:
    """
    SHA-256 of the derivation version and the given parts, as 64 hexadecimal
    characters.  Parts are joined with a separator that cannot occur in the
    values the planner passes (integers and validated names).
    """
    material = "|".join([_DERIVATION, *(str(part) for part in parts)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Draw:
    """One seeded stream of draws, identified by (seed, namespace, index)."""

    __slots__ = ("_random",)

    def __init__(self, seed: int, namespace: str, index: int) -> None:
        self._random = random.Random(int(derive_hex(seed, namespace, index), 16))

    def uniform(self) -> float:
        """A float in [0.0, 1.0)."""
        return self._random.random()

    def between(self, low: float, high: float) -> float:
        """A float in [low, high)."""
        return low + (high - low) * self.uniform()

    def index(self, size: int) -> int:
        """An integer in [0, size)."""
        if size < 1:
            raise ValueError("size must be at least 1")
        return min(int(self.uniform() * size), size - 1)

    def integer(self, low: int, high: int) -> int:
        """An integer in [low, high], both ends included."""
        if high < low:
            raise ValueError("high must not be below low")
        return low + self.index(high - low + 1)

    def choice(self, items: Sequence[T]) -> T:
        return items[self.index(len(items))]

    def weighted(self, items: Sequence[T], weights: Sequence[float]) -> T:
        """One of items, each with probability proportional to its weight."""
        if len(items) != len(weights) or not items:
            raise ValueError("items and weights must be non-empty and equally long")
        total = float(sum(weights))
        if total <= 0.0 or any(weight < 0.0 for weight in weights):
            raise ValueError("weights must be non-negative and not all zero")
        point = self.uniform() * total
        running = 0.0
        for item, weight in zip(items, weights):
            running += weight
            if point < running:
                return item
        return items[-1]

    def exponential(self, mean: float) -> float:
        """An exponentially distributed float with the given mean."""
        if mean <= 0.0:
            raise ValueError("mean must be positive")
        return -mean * math.log(1.0 - self.uniform())

    def lognormal(self, median: float, sigma: float) -> float:
        """A log-normally distributed float with the given median."""
        if median <= 0.0 or sigma < 0.0:
            raise ValueError("median must be positive and sigma non-negative")
        return median * math.exp(sigma * self._standard_normal())

    def _standard_normal(self) -> float:
        # Box-Muller.  1 - uniform() is in (0, 1], so the logarithm is defined.
        radius = math.sqrt(-2.0 * math.log(1.0 - self.uniform()))
        return radius * math.cos(2.0 * math.pi * self.uniform())
