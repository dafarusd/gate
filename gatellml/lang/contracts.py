"""Contracts: the deliberately tiny, decidable check fragment (SPEC section 4)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .origins import (
    OriginSet,
    TrackedValue,
    _norm,
    extract_atoms,
    value_of,
    origins_of,
)
from .origins import RECIPIENT_ARG_RE


@dataclass(frozen=True)
class OriginSubset:
    """origin(expr) must be admissible: User always; RequestSpan iff its
    normalized mention occurs in the operator's request text."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return f"missing argument '{self.arg}'"
        return origins_of(v).satisfies({request_norm})


@dataclass(frozen=True)
class NotTainted:
    """No secret-shaped material may appear in this argument."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return f"missing argument '{self.arg}'"
        if v.origin._taint_hit:
            return f"argument '{self.arg}' carries secret-shaped material"
        return None


@dataclass(frozen=True)
class AtomInRequest:
    """Every email/url/IBAN atom inside this argument traces to the request."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return f"missing argument '{self.arg}'"
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            atoms = extract_atoms(str(t))
            if not atoms:
                continue
            for a in atoms:
                if _norm(a) not in request_norm:
                    return f"target '{a[:40]}' does not trace to the user's request"
        return None


@dataclass(frozen=True)
class LenCheck:
    arg: str
    minimum: int

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return f"missing argument '{self.arg}'"
        if len(str(value_of(v))) < self.minimum:
            return f"argument '{self.arg}' too short"
        return None


@dataclass(frozen=True)
class RecipientTraceable:
    """Recipient-named argument: every target (raw value, or its extracted
    atoms when atom-shaped) must trace to the operator's request."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            s = str(t)
            atoms = extract_atoms(s)
            targets = atoms if atoms else ([s] if len(s) >= 3 else [])
            for a in targets:
                if _norm(a) not in request_norm:
                    return f"target '{a[:40]}' does not trace to the user's request"
        return None


@dataclass(frozen=True)
class AnyArgTraceable:
    """Mutation rule: at least one declared argument must trace to the
    operator's request (origin-based form of gate's destructive layer)."""
    args: tuple[str, ...]

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        for a in self.args:
            v = bindings.get(a)
            if v is None:
                continue
            ok = origins_of(v).satisfies({request_norm}) is None
            if not ok and isinstance(value_of(v), str):
                ok = len(str(value_of(v))) >= 3 and _norm(str(value_of(v))) in request_norm
            if ok:
                return None
        return "no mutation target traces to the user's request"


@dataclass(frozen=True)
class SpoofCheck:
    """No argument may claim prior user approval (gate's confirmation-spoof
    layer, retained verbatim for parity)."""

    SPOOF_RE = None

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        import re
        pat = re.compile(
            r"(user\s+(has\s+)?(confirmed|approved|agreed|said\s+yes)|"
            r"they\s+said\s+yes|confirmation\s*[:=]\s*(yes|true)|"
            r"already\s+(confirmed|approved)|approved\s+by\s+the\s+user)",
            re.IGNORECASE,
        )
        for k, v in bindings.items():
            val = value_of(v)
            texts = val if isinstance(val, (list, tuple)) else [val]
            if any(pat.search(str(t)) for t in texts):
                return f"argument '{k}' claims prior user approval"
        return None


@dataclass(frozen=True)
class DomainInRequest:
    """Every domain-shaped token in this argument (including scheme-less URLs)
    must appear in the operator's request. Closes the scheme-less-payload gap."""
    arg: str

    DOMAIN_RE = None

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        import re
        pat = re.compile(
            r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)*"
            r"\.(?:com|org|net|io|co|info|biz|site|online|xyz|me|us|uk|ca|de|fr|jp)\b",
            re.IGNORECASE,
        )
        v = bindings.get(self.arg)
        if v is None:
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            for dom in pat.findall(str(t)):
                if dom.lower() not in request_norm:
                    return f"domain '{dom}' does not trace to the user's request"
        return None


Contract = OriginSubset | NotTainted | AtomInRequest | LenCheck | RecipientTraceable | AnyArgTraceable | SpoofCheck | DomainInRequest


def contracts_from_dicts(dicts: list[dict[str, Any]]) -> list[Contract]:
    out: list[Contract] = []
    for d in dicts or []:
        kind = d.get("kind")
        if kind == "origin_subset":
            out.append(OriginSubset(d["arg"]))
        elif kind == "not_tainted":
            out.append(NotTainted(d["arg"]))
        elif kind == "atom_in_request":
            out.append(AtomInRequest(d["arg"]))
        elif kind == "recipient_traceable":
            out.append(RecipientTraceable(d["arg"]))
        elif kind == "any_arg_traceable":
            out.append(AnyArgTraceable(tuple(d.get("args", []))))
        elif kind == "domain_in_request":
            out.append(DomainInRequest(d["arg"]))
        elif kind == "len":
            out.append(LenCheck(d["arg"], int(d.get("minimum", 1))))
        else:
            raise ValueError(f"unknown contract kind: {kind!r}")
    return out


def evaluate_contract(
    contract: Contract, bindings: dict[str, TrackedValue], request_norm: str
) -> str | None:
    return contract.check(bindings, request_norm)
