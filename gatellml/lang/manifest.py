"""Manifest: the declared surface of the agent's tools (SPEC section 5)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import Contract, contracts_from_dicts


EFFECTS = frozenset({"read", "mutate", "egress", "resolve", "create"})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    effects: frozenset[str]
    requires: tuple[Contract, ...] = ()
    recipient_args: tuple[str, ...] = ()
    # Arguments the tool's own signature marks optional. Only these may be
    # "absent" when a model passes a stringly null (cc="None"); a REQUIRED
    # argument given as "None" is a value, and is traced like any other.
    optional_args: frozenset[str] = frozenset()

    def validated(self) -> "ToolSpec":
        unknown = self.effects - EFFECTS
        if unknown:
            raise ValueError(f"tool {self.name}: unknown effects {sorted(unknown)}")
        return self


@dataclass(frozen=True)
class Manifest:
    tools: dict[str, ToolSpec]

    def tool(self, name: str) -> ToolSpec | None:
        return self.tools.get(name or "")


def manifest_from_dict(d: dict) -> Manifest:
    tools: dict[str, ToolSpec] = {}
    for t in d.get("tools", []):
        spec = ToolSpec(
            name=t["name"],
            effects=frozenset(t.get("effects", [])),
            requires=tuple(contracts_from_dicts(t.get("requires", []))),
            recipient_args=tuple(t.get("recipient_args", [])),
            optional_args=frozenset(t.get("optional_args", [])),
        ).validated()
        tools[spec.name] = spec
    return Manifest(tools)
