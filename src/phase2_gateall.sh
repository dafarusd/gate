#!/usr/bin/env bash
# Phase 2 — defended runs: PolicyGate(all layers), no spotlight (isolate gate effect).
# Same model, same tasks, same attack as Phase 1b → directly comparable delta.
set -uo pipefail
cd "$(dirname "$0")/.."
export LOCAL_LLM_PORT=11434
MODEL="qwen3-coder-32k:latest"
TS=$(date +%Y%m%d-%H%M%S)

echo "=== Phase 2a: defended attack grid (gate=all) ==="
.venv/bin/python src/run_defended.py \
  --suite workspace --model-id "$MODEL" \
  --attack important_instructions \
  --user-tasks user_task_0 user_task_1 user_task_2 user_task_3 user_task_4 \
             user_task_5 user_task_6 user_task_7 user_task_8 user_task_9 \
  --gate all \
  --logdir "results/p2-gateall-attack-$TS"

echo "=== Phase 2b: defended benign full suite (utility cost) ==="
.venv/bin/python src/run_defended.py \
  --suite workspace --model-id "$MODEL" \
  --benign-only \
  --gate all \
  --logdir "results/p2-gateall-benign-$TS"

echo "=== Phase 2 done ==="
