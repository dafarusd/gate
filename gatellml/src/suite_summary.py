import json
import sys
from pathlib import Path


def summarize(logdir: Path) -> dict:
    all_json = list(logdir.rglob("*.json"))
    cells = [
        f for f in all_json
        if f.name.startswith("injection_task_")
        and len(f.parents) >= 3
        and f.parents[1].name.startswith("user_task_")
    ]
    benign = [
        f for f in all_json
        if f.name == "none.json"
        and len(f.parents) >= 2
        and f.parents[1].name.startswith("user_task_")
    ]
    calib = [f for f in all_json if f not in cells and f not in benign]
    total = len(cells)
    util = sec = blocks = butil = 0
    for f in cells:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        util += bool(d.get("utility"))
        sec += bool(d.get("security"))
        msgs = d.get("messages") or []
        for m in msgs:
            if m.get("role") == "tool" and m.get("error") and "BLOCKED" in str(m.get("error")):
                blocks += 1
                break
    for f in benign:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        butil += bool(d.get("utility"))

    return {
        "cells": total,
        "benign_cells": len(benign),
        "calib": len(calib),
        "utility": f"{util}/{total}" if total else "-",
        "benign_utility": f"{butil}/{len(benign)}" if benign else "-",
        "attack_success": f"{sec}/{total}" if total else "-",
        "episodes_with_blocks": blocks,
    }


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "gatellml/results")
    rows = []
    for d in sorted(p for p in root.iterdir() if p.is_dir() and p.name != "smoke"):
        r = summarize(d)
        if r["cells"] or r["benign_cells"]:
            rows.append((d.name, r))
    w = max(len(n) for n, _ in rows) if rows else 10
    print(f"{'arm'.ljust(w)}  attack  calib  utility  benign_utility  attack_success  blocks")
    for name, r in rows:
        print(f"{name.ljust(w)}  {r['cells']:>6}  {r['calib']:>5}  {r['utility']:>7}  {r['benign_utility']:>14}  {r['attack_success']:>14}  {r['episodes_with_blocks']:>6}")


if __name__ == "__main__":
    main()
