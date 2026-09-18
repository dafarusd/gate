"""Enforcement runtime: computes origins, evaluates contracts, renders verdicts.

SPEC sections 2, 4, 7. The model is never trusted; the program is.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .contracts import (
    AnyArgTraceable, AtomInRequest, DomainInRequest, OriginSubset, RecipientTraceable, TargetTraceable,
)
from .manifest import Manifest
from .origins import CREATES_RE, DOMAIN_RE, RECIPIENT_ARG_RE, Created, id_needs_naming, is_id_arg, OriginSet, leaks, numeric_named, object_nouns, top_level_id, ToolOrigin, TrackedValue, User, norm_request, traces, value_of


@dataclass
class Episode:
    """Per-check context derived from trusted surfaces only."""
    request_text: str
    # id -> object nouns of the allowed, non-read call that returned it (Addendum H)
    created: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def request_norm(self) -> str:
        return norm_request(self.request_text)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    violations: tuple[dict[str, Any], ...] = ()
    rule: str | None = None


def _mint_origin(text: str, ep: Episode, function: str = "", arg: str = "") -> OriginSet:
    t = str(text).strip()
    if is_id_arg(arg) and id_needs_naming(t):
        named = numeric_named(t, function, ep.request_norm)     # an id must be named AS an id
    else:
        # free text: a whole-token match, and long enough to mean something
        # ("a" is a token of every request and used to vouch for any mutation)
        named = len(t) >= 3 and traces(t, ep.request_norm)
        if not named and t.isascii() and t.isdigit() and not RECIPIENT_ARG_RE.search(arg or ""):
            named = traces(t, ep.request_norm)                  # amount=50 in "pay 50"; never user="2"
        if named and t.isascii() and t.isdigit() and len(t) < 4 and RECIPIENT_ARG_RE.search(arg or ""):
            named = False                                       # a 1-3 digit number is not a person
    if named:
        return OriginSet(frozenset({User()}))
    return OriginSet(frozenset({ToolOrigin(tool="<untracked>")}))


def observe_result(manifest: Manifest, ep: Episode, function: str, result_text: str) -> None:
    """Call with the result of every tool call the gate ALLOWED. Only a tool that
    CREATES mints an id: the manifest declares effect "create", or (auto-manifest)
    the tool's name starts with a creation verb. A tool that merely touched an
    existing object and echoed its id back mints nothing."""
    spec = manifest.tool(function)
    if spec is None:
        return
    if "create" not in spec.effects and not (CREATES_RE.match(function) and spec.effects - {"read", "resolve"}):
        return
    oid = top_level_id(result_text)
    if oid:
        ep.created[oid] = ep.created.get(oid, frozenset()) | object_nouns(function)


def bind_args(args: dict | None, ep: Episode, function: str = "",
              optional: frozenset[str] = frozenset()) -> dict[str, TrackedValue]:
    bindings: dict[str, TrackedValue] = {}
    for k, v in (args or {}).items():
        # JSON null is an absent argument. The stringly nulls models emit
        # (cc="None") are absent only for arguments the tool marks optional: on a
        # required argument "None" is a value, and dropping it made the
        # recipient check vanish (send_email(recipients="None") was ALLOWED).
        if v is None:
            continue
        if str(k) in optional and isinstance(v, str) and v.strip().lower() in ("", "none", "null"):
            continue
        if isinstance(v, (list, tuple)) and not v:     # an empty list names nothing and vouches for nothing
            continue
        vals = v if isinstance(v, (list, tuple)) else [v]
        origin = OriginSet()
        tainted = False
        for item in vals:
            # 2200.0 is the number the user typed as 2200; True is not an id
            s = str(int(item)) if isinstance(item, float) and item.is_integer() else str(item)
            if isinstance(item, bool) and is_id_arg(str(k)):
                s = ""
            # the argument CONTAINS a secret; the old test was reversed (s in secret),
            # so "key <secret>" passed and a benign "hunter" was blocked by "hunter2hunter2"
            if any(secret and leaks(secret, s) for secret in getattr(ep, "secrets", ())):
                tainted = True
            # noun binding: a created email id "34" never licenses delete_file("34")
            if s in ep.created and ep.created[s] & object_nouns(function):
                origin = origin.union(OriginSet(frozenset({Created(function)})))
            else:
                origin = origin.union(_mint_origin(s, ep, function, str(k)))
        bindings[str(k)] = TrackedValue(v, OriginSet(origin.items, tainted))
    return bindings


def enforce_call(
    manifest: Manifest,
    ep: Episode,
    function: str,
    args: dict | None,
    secrets: list[str] | None = None,
) -> Verdict:
    spec = manifest.tool(function)
    if spec is None:
        return Verdict(
            False,
            ({"violated": "undeclared_tool", "hint": f"tool '{function}' is not in the manifest"},),
            "undeclared_tool",
        )

    ep.secrets = set(secrets or ())
    try:
        bindings = bind_args(args, ep, function, spec.optional_args)
    finally:
        ep.secrets = set()

    violations: list[dict[str, Any]] = []

    # Every tool, not only declared egress: a "read" like get_webpage(url=...?d=<secret>)
    # is a GET request to a server the attacker chose.
    if secrets:
        blob = " ".join(
            str(x) for vs in (args or {}).values()
            for x in (vs if isinstance(vs, (list, tuple)) else [vs])
        )
        leaked = [s for s in secrets if leaks(s, blob)]
        if leaked:
            violations.append({
                "violated": "taint_egress",
                "actual": ["secret-shaped material"],
                "hint": "outbound arguments contain secret-shaped strings observed in tool output",
            })

    requires = list(spec.requires)
    if "egress" in spec.effects:
        # Egress completeness: an argument the policy author forgot is not a free
        # channel. travel.policy.v2 declared recipients/subject/body on send_email
        # and an undeclared cc=["mallory@evil.com"] walked straight out. Only a
        # contract that TRACES covers an argument: NotTainted(cc) or a domain check
        # on cc left cc=["mallory"] uncovered while looking declared.
        def declared(arg: str, *kinds) -> bool:
            return any(isinstance(c, kinds) and (getattr(c, "arg", None) == arg or arg in getattr(c, "args", ()))
                       for c in requires)
        def has_host(k: str) -> bool:
            v = value_of(bindings[k])
            return any(DOMAIN_RE.search(str(t)) for t in (v if isinstance(v, (list, tuple)) else [v]))
        for k in bindings:
            if RECIPIENT_ARG_RE.search(k):
                # A domain check covers a destination that IS a host (open_url(url=...)).
                # It does not cover one that holds no host at all: cc=["mallory"].
                if declared(k, DomainInRequest) and has_host(k):
                    continue
                if not declared(k, RecipientTraceable, TargetTraceable, OriginSubset, AnyArgTraceable):
                    requires.append(RecipientTraceable(k))
            else:
                if not declared(k, AtomInRequest, RecipientTraceable, TargetTraceable, OriginSubset):
                    requires.append(AtomInRequest(k))
                if not declared(k, DomainInRequest, RecipientTraceable, TargetTraceable, OriginSubset):
                    requires.append(DomainInRequest(k, urlish_only=True))

    for c in requires:
        why = c.check(bindings, ep.request_norm)
        if why is not None:
            violations.append({
                "violated": type(c).__name__,
                "arg": getattr(c, "arg", None),
                "hint": why,
            })

    if violations:
        return Verdict(False, tuple(violations), violations[0].get("violated"))
    return Verdict(True)


BLOCK_MSG = (
    "BLOCKED by security policy ({rule}). This action was not explicitly "
    "requested by the user (targets must be named in the user's original "
    "request). Do not retry this exact action; continue with the rest of "
    "the task or ask the user for confirmation."
)


def render_block(verdict: Verdict) -> str:
    detail = "; ".join(v.get("hint", "") for v in verdict.violations[:2])
    return BLOCK_MSG.format(rule=verdict.rule) + (" Detail: " + detail if detail else "")
