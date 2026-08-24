"""Complete a hand-authored policy manifest with the suite's undeclared read tools.

Why this exists
---------------
gatellm's runtime denies by default: `enforce_call` refuses any tool absent from the
manifest with rule `undeclared_tool`. Addendum B's hand-authored manifests declared only
the tools implicated in the breach mechanisms (travel: 6 of 28; slack: 7 of 11), so every
undeclared *read* was refused too. Reads are what carry the injection payload, so the
payload never reached the model and the resulting 0/21 and 0/15 were vacuous-by-incapacity
rather than contract-mediated closures.

The correction is deliberately additive: existing declarations are copied through
byte-for-byte, and the only new entries are `read`-effect tools with no contract. Nothing
under test is retuned, so if a suite still breaches after this, the contracts genuinely
failed to cover it.

`EGRESS_ADJACENT_READS` names reads that leave the episode (fetching an attacker-controlled
URL is how a read exfiltrates). Those keep a domain_in_request contract instead of flowing
free. Everything else is internal state observation.

Usage:
    python gatellml/src/complete_manifest.py <suite> <in.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suite

BENCHMARK_VERSION = "v1.2"

# Reads that reach outside the episode: gated on the URL tracing to the request.
EGRESS_ADJACENT_READS = {"get_webpage"}


def suite_tool_names(suite: str) -> list[str]:
    return sorted(t.name for t in get_suite(BENCHMARK_VERSION, suite).tools)


def complete(suite: str, src: Path) -> dict:
    doc = json.loads(src.read_text())
    declared = {t["name"] for t in doc["tools"]}
    missing = [n for n in suite_tool_names(suite) if n not in declared]

    added = []
    for name in missing:
        spec: dict = {"name": name, "effects": ["read"]}
        if name in EGRESS_ADJACENT_READS:
            spec["requires"] = [{"kind": "domain_in_request", "arg": "url"}]
        added.append(spec)

    return {"tools": doc["tools"] + added}, missing


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    suite, src, dst = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    doc, missing = complete(suite, src)
    dst.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"{suite}: {len(doc['tools'])} tools declared "
          f"({len(missing)} reads added) -> {dst}")
    for n in missing:
        print(f"  + {n}")


if __name__ == "__main__":
    main()
