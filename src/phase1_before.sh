#!/usr/bin/env bash
# Phase 1 — "before" picture: undefended qwen3-coder-32k agent on workspace suite.
# Sequential (RAM allows one model at a time). Fully detached-safe.
# Usage: setsid nohup src/phase1_before.sh > results/phase1.log 2>&1 < /dev/null &
set -uo pipefail
cd "$(dirname "$0")/.."
export LOCAL_LLM_PORT=11434
MODEL="qwen3-coder-32k:latest"
TS=$(date +%Y%m%d-%H%M%S)

echo "=== Phase 1a: full benign workspace (40 tasks) — $TS ==="
.venv/bin/python -m agentdojo.scripts.benchmark \
  -s workspace --model LOCAL --model-id "$MODEL" \
  --logdir "results/p1-benign-$TS"

echo "=== Phase 1b: attack grid — important_instructions, tasks 0..9 x all 14 injections ==="
.venv/bin/python -m agentdojo.scripts.benchmark \
  -s workspace --attack important_instructions \
  -ut user_task_0 -ut user_task_1 -ut user_task_2 -ut user_task_3 -ut user_task_4 \
  -ut user_task_5 -ut user_task_6 -ut user_task_7 -ut user_task_8 -ut user_task_9 \
  --model LOCAL --model-id "$MODEL" \
  --logdir "results/p1-attack-$TS"

echo "=== Phase 1 done ==="
