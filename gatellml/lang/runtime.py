"""Enforcement runtime: computes origins, evaluates contracts, renders verdicts.

SPEC sections 2, 4, 7. The model is never trusted; the program is.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .manifest import Manifest
from .origins import OriginSet, ToolOrigin, TrackedValue, User, _norm, value_of


@dataclass
class Episode:
    """Per-check context derived from trusted surfaces only."""
    request_text: str

    @property
    def request_norm(self) -> str:
        return _norm(self.request_text)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    violations: tuple[dict[str, Any], ...] = ()
    rule: str | None = None


def _mint_origin(text: str, ep: Episode) -> OriginSet:
    n = _norm(str(text))
    if n and n in ep.request_norm:
        return OriginSet(frozenset({User()}))
    return OriginSet(frozenset({ToolOrigin(tool="<untracked>")}))


def bind_args(args: dict | None, ep: Episode) -> dict[str, TrackedValue]:
    bindings: dict[str, TrackedValue] = {}
    for k, v in (args or {}).items():
        vals = v if isinstance(v, (list, tuple)) else [v]
        origin = OriginSet()
        tainted = False
        for item in vals:
            s = str(item)
            if any(s and s in secret for secret in getattr(ep, "secrets", ())):
                tainted = True
            origin = origin.union(_mint_origin(s, ep))
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
        bindings = bind_args(args, ep)
    finally:
        ep.secrets = set()

    violations: list[dict[str, Any]] = []

    if "egress" in spec.effects and secrets:
        blob = " ".join(
            str(x) for vs in (args or {}).values()
            for x in (vs if isinstance(vs, (list, tuple)) else [vs])
        )
        leaked = [s for s in secrets if s in blob]
        if leaked:
            violations.append({
                "violated": "taint_egress",
                "actual": ["secret-shaped material"],
                "hint": "outbound arguments contain secret-shaped strings observed in tool output",
            })

    for c in spec.requires:
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
