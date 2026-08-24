import json
import sys
from pathlib import Path


def load_cells(logdir: Path) -> dict[str, dict]:
    out = {}
    for f in logdir.rglob("*.json"):
        if not f.name.startswith("injection_task_") or len(f.parents) < 3:
            continue
        if not f.parents[1].name.startswith("user_task_"):
            continue
        key = f"{f.parents[2].name}/{f.parents[1].name}/{f.name}"
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        blocked = any(
            m.get("role") == "tool" and "BLOCKED" in str(m.get("error"))
            for m in (d.get("messages") or [])
        )
        out[key] = {
            "utility": bool(d.get("utility")),
            "attack_success": bool(d.get("security")),
            "blocked": blocked,
        }
    return out


def main() -> None:
    a_dir, b_dir = Path(sys.argv[1]), Path(sys.argv[2])
    a_name, b_name = a_dir.name, b_dir.name
    a, b = load_cells(a_dir), load_cells(b_dir)
    shared = sorted(set(a) & set(b))
    if not shared:
        print("no overlapping cells")
        return
    print(f"matched cells: {len(shared)}  ({a_name} vs {b_name})")
    header = f"{'cell':<44} {'atk A/B':>7} {'util A/B':>8} {'blk A/B':>7}"
    print(header)
    diffs = 0
    for c in shared:
        ca, cb = a[c], b[c]
        mark = "" if (ca["utility"], ca["attack_success"]) == (cb["utility"], cb["attack_success"]) else " <<"
        if mark:
            diffs += 1
            print(
                f"{c:<44} {int(ca['attack_success'])}/{int(cb['attack_success']):>3} "
                f"{int(ca['utility'])}/{int(cb['utility']):>4} "
                f"{int(ca['blocked'])}/{int(cb['blocked']):>4}{mark}"
            )
    ua = sum(a[c]["utility"] for c in shared)
    ub = sum(b[c]["utility"] for c in shared)
    aa = sum(a[c]["attack_success"] for c in shared)
    ab = sum(b[c]["attack_success"] for c in shared)
    ba = sum(a[c]["blocked"] for c in shared)
    bb = sum(b[c]["blocked"] for c in shared)
    print(f"totals: attack {aa} vs {ab} | utility {ua} vs {ub} | blocked-episodes {ba} vs {bb}")
    print(f"cells differing on (utility, security): {diffs}")


if __name__ == "__main__":
    main()
