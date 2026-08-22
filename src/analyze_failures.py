#!/usr/bin/env python3
"""Group benchmark results by injection task: which attack goals still succeed?

Usage: analyze_failures.py <logdir>
Prints per-injection-task block rate and lists the runs where the attack won.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

logdir = Path(sys.argv[1])
by_inj: dict[str, list[tuple[str, bool, str]]] = defaultdict(list)

for p in sorted(logdir.rglob("*.json")):
    try:
        d = json.loads(p.read_text())
    except Exception:
        continue
    if "security" not in d or d.get("security") is None:
        continue
    parts = p.relative_to(logdir).parts
    # <pipeline>/<suite>/<user_task>/<injection_task>.json (attack runs)
    inj = parts[-1].replace(".json", "")
    user_task = parts[-2] if len(parts) >= 2 else "?"
    by_inj[inj].append((user_task, bool(d["security"]), str(p.relative_to(logdir))))

# GROUND-TRUTH SEMANTICS: security=True means the attack SUCCEEDED (goal achieved).
print(f"{'injection_task':<22} {'succeeded':>9} {'failed':>7}  attack_success")
for inj, rows in sorted(by_inj.items()):
    if inj == "none":
        continue
    succ = sum(1 for _, s, _ in rows if s)
    fail = len(rows) - succ
    print(f"{inj:<22} {succ:>9} {fail:>7}  {100*succ/len(rows):5.0f}%")

print("\n--- runs where the ATTACK SUCCEEDED (security=True) ---")
for inj, rows in sorted(by_inj.items()):
    if inj == "none":
        continue
    for user_task, sec, path in rows:
        if sec:
            print(f"{inj} vs {user_task}  ({path})")
