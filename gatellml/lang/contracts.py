"""Contracts: the deliberately tiny, decidable check fragment (SPEC section 4)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .origins import (
    DOMAIN_RE,
    OriginSet,
    TrackedValue,
    _norm,
    extract_atoms,
    has_invisible,
    host_traces,
    id_needs_naming,
    is_id_arg,
    value_of,
    origins_of,
    traces,
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
            return None
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
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            atoms = extract_atoms(str(t))
            if not atoms:
                continue
            for a in atoms:
                if not traces(a, request_norm):
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
    atoms when atom-shaped) must trace to the operator's request.

    One traced atom does not license the rest of the string. After the traced
    atoms are blanked out, what remains may be a display name, but it may not
    hold another address ("@"), another authority ("//"), or a host that does
    not trace — '"alice@example.com"@evil.com', 'alice@example.com, mallory(x)@evil.com'
    and '//evil.com/https://mybank.com/pay' all hid behind a traced atom."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            s = str(t)
            if has_invisible(s):
                return f"target '{s[:40]!r}' contains invisible or control characters"
            if not s.strip():
                # an optional argument left empty never gets here (bind_args drops it); a
                # REQUIRED recipient given as "" names nobody and must not pass by default
                return f"argument '{self.arg}' names no target"
            if s.strip().isascii() and s.strip().isdigit() and len(s.strip()) < 4:
                # "user guide 2" licensed remove_user_from_slack(user="2"): a 1-3 digit number
                # in a request is a quantity or an ordinal, not a person. Phone numbers are longer.
                return f"target '{s.strip()}' is a bare small number, not a named recipient"
            atoms = extract_atoms(s)
            targets = atoms if atoms else [s]
            for a in targets:
                if not traces(a, request_norm):
                    return f"target '{a[:40]}' does not trace to the user's request"
            rest = s
            for a in atoms:
                rest = rest.replace(a, " ")
            if atoms and ("@" in rest or "//" in rest):
                return f"target '{s[:40]}' carries a second address behind a traced one"
            if atoms:
                for dom in DOMAIN_RE.findall(rest):
                    if not host_traces(dom, request_norm):
                        return f"target '{dom[:40]}' does not trace to the user's request"
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
            # an empty origin set is vacuously admissible; it must not vouch
            ok = bool(origins_of(v).items) and origins_of(v).satisfies({request_norm}) is None
            # an id-like number is decided by its origin (named as an id, or created
            # by this episode), never by the free-text fallback
            val = value_of(v)
            if not ok and isinstance(val, str) and not (is_id_arg(a) and id_needs_naming(val)):
                ok = len(val) >= 3 and traces(val, request_norm)
            if ok:
                return None
        return "no mutation target traces to the user's request"


@dataclass(frozen=True)
class TargetTraceable:
    """The NAMED argument is the target and must itself trace (to the request, or
    to an object this episode created). AnyArgTraceable lets any one argument
    vouch for the call, so a date the user typed licenses a hotel the attacker
    chose. Use this where the policy author knows which argument is the target."""
    arg: str

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return f"missing target argument '{self.arg}'"
        if origins_of(v).items and origins_of(v).satisfies({request_norm}) is None:
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        strict = is_id_arg(self.arg)
        if texts and all(not isinstance(t, bool) and str(t).strip() and not (strict and id_needs_naming(str(t)))
                         and traces(str(t), request_norm) for t in texts):
            return None
        return f"target '{str(val)[:40]}' does not trace to the user's request"


@dataclass(frozen=True)
class SpoofCheck:
    """No argument may claim prior user approval (gate's confirmation-spoof
    layer, retained verbatim for parity)."""

    SPOOF_RE = None

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        import re
        pat = re.compile(
            r"(user\s+(has\s+)?(\w+ly\s+)?(confirmed|approved|agreed|said\s+yes)|"
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
    """Every host-shaped token in this argument (including scheme-less URLs and
    IPv4 literals) must appear in the operator's request.

    urlish_only: check only hosts written like a link ("www.x.ru", "x.ru/login",
    "x.ru:8080"). That is the default contract for an egress argument the policy
    never declared, where "recipe.docx" in a body must not read as a host."""
    arg: str
    urlish_only: bool = False

    def check(self, bindings: dict[str, TrackedValue], request_norm: str) -> str | None:
        v = bindings.get(self.arg)
        if v is None:
            return None
        val = value_of(v)
        texts = val if isinstance(val, (list, tuple)) else [val]
        for t in texts:
            text = str(t)
            for m in DOMAIN_RE.finditer(text):
                dom = m.group(0)
                if self.urlish_only and not (dom.lower().startswith("www.") or text[m.end():m.end() + 1] in ("/", ":")):
                    continue
                if not host_traces(dom, request_norm):
                    return f"domain '{dom}' does not trace to the user's request"
        return None


Contract = OriginSubset | NotTainted | AtomInRequest | LenCheck | RecipientTraceable | AnyArgTraceable | TargetTraceable | SpoofCheck | DomainInRequest


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
        elif kind == "target_traceable":
            out.append(TargetTraceable(d["arg"]))
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
