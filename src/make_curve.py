#!/usr/bin/env python3
"""Generate the capability-vs-attack-success table (+ optional chart) from ladder runs.

ASCII table always; PNG chart if matplotlib is available.
Usage: make_curve.py
"""
from __future__ import annotations

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

# (label, attack-ungated dir, attack-gated dir, benign-ungated dir)
POINTS = [
    ("qwen3-5-9b",        "ladder-qwen3-5-9b-ungated",        "ladder-qwen3-5-9b-gated",        "ladder-qwen3-5-9b-benign-ungated"),
    ("qwen3-6-35b-a3b",   "ladder-qwen3-6-35b-a3b-ungated",   "ladder-qwen3-6-35b-a3b-gated",   "ladder-qwen3-6-35b-a3b-benign-ungated"),
    ("qwen3-next-80b",    "ladder-qwen3-next-80b-ungated",    "ladder-qwen3-next-80b-gated",    "ladder-qwen3-next-80b-benign-ungated"),
    ("qwen3-235b-a22b",   "ladder-qwen3-235b-a22b-instruct-2507-ungated", "ladder-qwen3-235b-a22b-instruct-2507-gated", "ladder-qwen3-235b-a22b-instruct-2507-benign-ungated"),
    ("qwen3-coder-480b",  "v2-venice-undefended-clean",       "v3-venice-gateall",              "v4-venice-benign-ungated"),
]


def rates(logdir: Path):
    if not logdir.exists():
        return None, None, None
    util, atk, vacuous = [], [], 0
    for p in logdir.rglob("*.json"):
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if d.get("utility") is not None:
            util.append(bool(d["utility"]))
        parts = p.relative_to(logdir).parts
        if d.get("security") is not None:
            if any(x in parts for x in ("important_instructions",)) or "holdout" in str(p):
                atk.append(bool(d["security"]))
            else:
                vacuous += 1
    u = 100 * sum(util) / len(util) if util else None
    a = 100 * sum(atk) / len(atk) if atk else None
    return u, a, len(atk)


def main():
    rows = []
    for label, un, ga, ben in POINTS:
        u_atk, a_un, n_un = rates(RESULTS / un)
        _, a_ga, n_ga = rates(RESULTS / ga)
        u_ben, _, _ = rates(RESULTS / ben)
        rows.append((label, u_ben, u_atk, a_un, n_un, a_ga, n_ga))

    print(f"{'model':<20} {'benignUtil':>10} {'util@atk':>9} {'ATK-success':>12} {'(n)':>5} {'gated':>7} {'(n)':>5}")
    for label, u_ben, u_atk, a_un, n_un, a_ga, n_ga in rows:
        f = lambda x: f"{x:.1f}%" if x is not None else "—"
        print(f"{label:<20} {f(u_ben):>10} {f(u_atk):>9} {f(a_un):>12} {n_un or 0:>5} {f(a_ga):>7} {n_ga or 0:>5}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        pts = [(u_ben, a_un) for _, u_ben, _, a_un, _, _, _ in rows if u_ben is not None and a_un is not None]
        if len(pts) >= 2:
            fig, ax = plt.subplots(figsize=(7, 5))
            ax.scatter([p[0] for p in pts], [p[1] for p in pts], s=90, zorder=3)
            for (x, y), (label, *_rest) in zip(pts, rows):
                ax.annotate(label, (x, y), textcoords="offset points", xytext=(8, 6), fontsize=9)
            ax.set_xlabel("capability (benign utility, %)")
            ax.set_ylabel("attack success, undefended (%)")
            ax.set_title("Attack success does NOT track capability smoothly\n(same family, same harness, same attacks)")
            ax.grid(alpha=0.3)
            out = RESULTS / "capability-curve.png"
            fig.tight_layout()
            fig.savefig(out, dpi=140)
            print(f"\nchart -> {out}")
    except ImportError:
        print("\n(matplotlib not installed — table only)")


if __name__ == "__main__":
    main()
