#!/usr/bin/env python3
"""Aggregate AgentDojo run logs into a results table.

Walks a logdir tree (runs/<pipeline>/<suite>/<user_task>/[<attack>/<injection_task>/]run.json)
and emits per-run utility/security plus summary rows. Pure file reading; safe anytime.

Usage: aggregate.py <logdir> [--csv out.csv]
"""
import json
import sys
from pathlib import Path


def iter_runs(logdir: Path):
    for p in sorted(logdir.rglob("*.json")):
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if "utility" not in d and "security" not in d:
            continue
        rel = p.relative_to(logdir)
        parts = rel.parts
        # .../<pipeline>/<suite>/<user_task>/<attack-name-or-none>/<inj-or-none>.json
        yield {
            "pipeline": parts[0] if len(parts) > 0 else "?",
            "suite": parts[1] if len(parts) > 1 else "?",
            "user_task": parts[2] if len(parts) > 2 else "?",
            "attack_cell": parts[3] if len(parts) > 3 else "",
            "utility": bool(d.get("utility")) if d.get("utility") is not None else None,
            "security": (bool(d.get("security")) if d.get("security") is not None else None),
            "path": str(rel),
        }


def main():
    logdir = Path(sys.argv[1])
    runs = list(iter_runs(logdir))
    if not runs:
        print("no runs found")
        return
    n = len(runs)
    util = [r for r in runs if r["utility"] is not None]
    sec = [r for r in runs if r["security"] is not None]
    u_pct = 100 * sum(r["utility"] for r in util) / len(util) if util else float("nan")
    # GROUND-TRUTH SEMANTICS (verified in agentdojo/task_suite/task_suite.py:412):
    # the `security` field = injection_task.security() = True iff the ATTACK GOAL
    # was achieved. So security=True means attack SUCCEEDED (bad).
    # attack_success_rate = mean(security). safety = 100 - that.
    atk = [r for r in sec if r["attack_cell"] not in ("none", "")]
    a_pct = 100 * sum(r["security"] for r in atk) / len(atk) if atk else float("nan")
    print(f"runs={n}  utility={u_pct:.1f}% (n={len(util)})  "
          f"ATTACK-SUCCESS={a_pct:.1f}% (n={len(atk)} attack cells; {len(sec)-len(atk)} vacuous benign excluded)")
    print(f"{'suite':<10} {'user_task':<14} {'attack_cell':<12} {'util':<6} {'attack_won':<10}")
    for r in runs:
        print(f"{r['suite']:<10} {r['user_task']:<14} {r['attack_cell'][:12]:<12} "
              f"{str(r['utility']):<6} {str(r['security']):<6}")
    if "--csv" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--csv") + 1])
        import csv
        with out.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["pipeline", "suite", "user_task", "attack_cell", "utility", "security", "path"])
            w.writeheader()
            w.writerows(runs)
        print(f"csv -> {out}")


if __name__ == "__main__":
    main()
