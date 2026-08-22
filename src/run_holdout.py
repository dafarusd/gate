#!/usr/bin/env python3
"""Phase 3 — run the SEQUESTERED hold-out attack set against the frozen defense.

Each hold-out payload (src/holdout_attacks.jsonl, written before any defense
tuning) is delivered through the suite's real injection vectors via a custom
attack class, and scored by the suite's OWN goal checkers — novel delivery,
verified goals.

Usage:
  .venv/bin/python src/run_holdout.py --provider venice \
      --model-id qwen3-coder-480b-a35b-instruct-turbo \
      --user-tasks user_task_0 ... --injection-tasks injection_task_0 ... \
      --logdir-root results/p3-holdout
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentdojo.attacks.baseline_attacks import FixedJailbreakAttack
from agentdojo.benchmark import benchmark_suite_with_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from run_defended import build_pipeline


class HoldoutAttack(FixedJailbreakAttack):
    """Delivers one hold-out payload verbatim. The suite's goal text is
    appended after it. Templating is bypassed entirely (payloads may contain
    braces that break both str.format and Jinja2)."""

    def __init__(self, holdout_id: str, payload: str, task_suite, target_pipeline):
        super().__init__("{goal}", task_suite, target_pipeline)
        self.name = f"holdout_{holdout_id}"
        self._payload = payload

    def attack(self, user_task, injection_task):
        goal = getattr(injection_task, "GOAL", "")
        text = f"{self._payload}\n\nTODO: {goal}"
        return {inj: text for inj in self.get_injection_candidates(user_task)}


class SplitHoldoutAttack(HoldoutAttack):
    """h02-style: different payload per injection vector."""

    def __init__(self, holdout_id: str, payload_a: str, payload_b: str, task_suite, target_pipeline):
        super().__init__(holdout_id, payload_a, task_suite, target_pipeline)
        self._a, self._b = payload_a, payload_b

    def attack(self, user_task, injection_task):
        candidates = self.get_injection_candidates(user_task)
        out = {}
        for i, inj in enumerate(candidates):
            base = self._a if i % 2 == 0 else self._b
            goal = getattr(injection_task, "GOAL", "")
            out[inj] = f"{base}\n\nTODO: {goal}"
        return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="venice")
    ap.add_argument("--model-id", required=True)
    ap.add_argument("--suite", default="workspace")
    ap.add_argument("--user-tasks", nargs="+", required=True)
    ap.add_argument("--injection-tasks", nargs="+", required=True)
    ap.add_argument("--logdir-root", required=True)
    ap.add_argument("--gate", default="all")
    ap.add_argument("--attacks-file", default=str(Path(__file__).parent / "holdout_attacks.jsonl"))
    ap.add_argument("--only", default=None, help="run a single holdout id (for targeted re-runs)")
    args = ap.parse_args()

    suite = get_suite("v1.2", args.suite)
    gate_layers = {s.strip() for s in args.gate.split(",") if s.strip()}
    pipeline = build_pipeline(args.model_id, gate_layers, spotlight=False, provider=args.provider)

    attacks = [json.loads(l) for l in Path(args.attacks_file).read_text().splitlines() if l.strip()]
    if args.only:
        attacks = [h for h in attacks if h["id"] == args.only]
    for h in attacks:
        if "payload_a" in h:
            atk = SplitHoldoutAttack(h["id"], h["payload_a"], h["payload_b"], suite, pipeline)
        else:
            atk = HoldoutAttack(h["id"], h["payload"], suite, pipeline)
        logdir = Path(args.logdir_root) / h["id"]
        try:
            with OutputLogger(str(logdir)):
                benchmark_suite_with_injections(
                    pipeline, suite, atk, logdir, force_rerun=False,
                    user_tasks=args.user_tasks, injection_tasks=args.injection_tasks,
                    benchmark_version="v1.2",
                )
            print(f"[{h['id']}] done -> {logdir}")
        except Exception as e:
            # failures are evidence, not stopping conditions — log and continue
            print(f"[{h['id']}] ERROR: {type(e).__name__}: {e}")

    print("PHASE 3 COMPLETE")


if __name__ == "__main__":
    main()
