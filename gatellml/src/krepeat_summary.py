import json
import sys
from pathlib import Path


def cell_result(logdir: Path) -> dict | None:
    files = [
        f for f in logdir.rglob("*.json")
        if f.name.startswith("injection_task_")
        and len(f.parents) >= 3
        and f.parents[1].name.startswith("user_task_")
    ]
    if not files:
        return None
    d = json.loads(files[0].read_text())
    blocked = any(
        m.get("role") == "tool" and "BLOCKED" in str(m.get("error"))
        for m in (d.get("messages") or [])
    )
    return {"utility": bool(d.get("utility")), "attack_success": bool(d.get("security")), "blocked": blocked}


def main() -> None:
    root = Path(sys.argv[1])
    groups = {}
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        parts = d.name.rsplit("-r", 1)
        if len(parts) == 2:
            groups.setdefault(parts[0], []).append(cell_result(d))
    print(f"{'group':<22} {'n':>3} {'attack_success':>14} {'utility':>8} {'blocks':>7}")
    for g, rs in sorted(groups.items()):
        rs = [r for r in rs if r]
        n = len(rs)
        if not n:
            continue
        atk = sum(r["attack_success"] for r in rs)
        util = sum(r["utility"] for r in rs)
        blk = sum(r["blocked"] for r in rs)
        print(f"{g:<22} {n:>3} {atk:>5}/{n:<8} {util:>3}/{n:<4} {blk:>7}")
        rates = [r["attack_success"] for r in rs]
        mean = sum(rates) / n
        var = sum((x - mean) ** 2 for x in rates) / max(n - 1, 1)
        print(f"{'  attack-success rate':<22} {mean:.2f} ± {var ** 0.5:.2f} (n={n})")


if __name__ == "__main__":
    main()
