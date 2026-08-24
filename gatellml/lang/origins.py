"""Origin tracking: every value carries the attested sources it was derived from.

Spec reference: gatellml/SPEC.md sections 2 and 7.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL_RE = re.compile(r"https?://[^\s]+")
IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")

RECIPIENT_ARG_RE = re.compile(
    r"recipients?|to|email|address|user(name)?|channel|url|iban|account|payee|contact|attendees?|participant",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S{8,}"),
    re.compile(r"\b[0-9a-f]{40,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


@dataclass(frozen=True)
class User:
    pass


@dataclass(frozen=True)
class RequestSpan:
    """An entity resolved from a mention in the operator's request."""
    mention: str


@dataclass(frozen=True)
class ToolOrigin:
    tool: str


@dataclass(frozen=True)
class Derived:
    sources: tuple["Origin", ...] = field(default_factory=tuple)


Origin = User | RequestSpan | ToolOrigin | Derived


@dataclass(frozen=True)
class OriginSet:
    items: frozenset[Origin] = frozenset()

    def union(self, other: "OriginSet") -> "OriginSet":
        return OriginSet(self.items | other.items)

    def has_user(self) -> bool:
        return any(isinstance(o, User) for o in self.items)

    def user_spans(self) -> list[str]:
        return [o.mention for o in self.items if isinstance(o, RequestSpan)]

    def is_tainted(self) -> bool:
        return any(isinstance(o, ToolOrigin) for o in self.items) and self._taint_hit

    _taint_hit: bool = False

    def with_taint(self) -> "OriginSet":
        return OriginSet(self.items, True)

    def flatten(self) -> set[Origin]:
        out: set[Origin] = set()
        for o in self.items:
            if isinstance(o, Derived):
                out |= o.sources
            else:
                out.add(o)
        return OriginSet(frozenset(out), self._taint_hit).items

    def satisfies(self, allowed_user_spans: set[str]) -> str | None:
        """Return None if every origin is admissible under a flow policy that
        admits User origins and RequestSpans resolving into allowed_user_spans
        (the normalized request text); else a human-readable violation."""
        for o in self.flatten():
            if isinstance(o, User):
                continue
            if isinstance(o, RequestSpan):
                if _norm(o.mention) in allowed_user_spans:
                    continue
                return f"resolved entity '{o.mention}' does not trace to the user's request"
            return "value originates from tool output, not from the user's request"
        return None


@dataclass(frozen=True)
class TrackedValue:
    value: Any
    origin: OriginSet = OriginSet()

    def map_text(self, fn) -> "TrackedValue":
        if isinstance(self.value, str):
            return TrackedValue(fn(self.value), self.origin)
        return self


def track(value: Any, origin: OriginSet | None = None) -> TrackedValue:
    return TrackedValue(value, origin or OriginSet())


def value_of(v: TrackedValue | Any) -> Any:
    return v.value if isinstance(v, TrackedValue) else v


def origins_of(v: TrackedValue | Any) -> OriginSet:
    return v.origin if isinstance(v, TrackedValue) else OriginSet()


def extract_atoms(text: str) -> list[str]:
    atoms: list[str] = []
    for pat in (EMAIL_RE, URL_RE, IBAN_RE):
        atoms.extend(pat.findall(text))
    return atoms


def find_secrets(text: str) -> list[str]:
    found: list[str] = []
    for pat in SECRET_PATTERNS:
        for m in pat.findall(text):
            s = m if isinstance(m, str) else m[0]
            if re.match(r"(?i)password|api|token|secret", s):
                s = re.split(r"[:=]", s, maxsplit=1)[-1].strip()
            if len(s) >= 8:
                found.append(s)
    return found
