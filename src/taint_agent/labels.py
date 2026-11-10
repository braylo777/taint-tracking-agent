"""Taint labels and labelled values.

Every value the agent handles is a TV (tainted value): the raw value plus the
set of sources it was derived from. Labels only ever grow when values combine.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Trust(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Label:
    source: str  # "user", "contacts", "email:e1", "web:https://...", "doc:d1"
    trust: Trust
    confidential: bool = False


USER = Label("user", Trust.TRUSTED)


@dataclass(frozen=True)
class TV:
    value: object
    labels: frozenset = frozenset()

    @property
    def tainted(self) -> bool:
        return any(lab.trust is Trust.UNTRUSTED for lab in self.labels)

    @property
    def confidential(self) -> bool:
        return any(lab.confidential for lab in self.labels)

    def untrusted_sources(self) -> list[str]:
        return sorted(lab.source for lab in self.labels if lab.trust is Trust.UNTRUSTED)


def trusted(value: object) -> TV:
    """A literal that came from the user's own request."""
    return TV(value, frozenset({USER}))


def join(*tvs: TV) -> frozenset:
    out: set = set()
    for tv in tvs:
        out |= tv.labels
    return frozenset(out)


def derive(value: object, *inputs: TV) -> TV:
    """Any value computed from inputs carries the union of their labels."""
    return TV(value, join(*inputs))
