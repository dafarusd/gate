#!/usr/bin/env python3
"""Run the shared gate vectors against the Python runtime. Prints 'N/N agree'.
The Kotlin port runs the same file (SharedVectorsTest.kt in Agent Ultra)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from gatellml.lang.manifest import manifest_from_dict  # noqa: E402
from gatellml.lang.origins import find_secrets  # noqa: E402
from gatellml.lang.runtime import Episode, enforce_call  # noqa: E402

doc = json.loads((Path(__file__).resolve().parent / "vectors" / "gate_vectors.json").read_text())
wrong = []
for v in doc["vectors"]:
    secrets = [s for t in v["tool_results"] for s in find_secrets(t)]
    verdict = enforce_call(manifest_from_dict({"tools": v["tools"]}), Episode(v["request"]), v["function"], v["args"], secrets)
    if verdict.allowed != (v["expect"] == "allow"):
        wrong.append(f"{v['name']} -> {'ALLOW' if verdict.allowed else 'BLOCK'}")
print("\n".join(wrong))
print(f"{len(doc['vectors']) - len(wrong)}/{len(doc['vectors'])} agree")
raise SystemExit(1 if wrong else 0)
