#!/usr/bin/env bash
# Minimal decisive reproduction: focused adaptive grid, undefended vs gated,
# then the summary table. Frontier arm requires VENICE_API_KEY.
set -uo pipefail
cd "$(dirname "$0")/.."
MODEL="qwen3-coder-480b-a35b-instruct-turbo"
UT="user_task_2 user_task_4"   # compliance-proven tasks — attacks reach the tools

echo "== 1/2 undefended =="
.venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$MODEL" \
  --suite workspace --attack important_instructions --user-tasks $UT \
  --gate none --logdir results/repro-ungated

echo "== 2/2 gated =="
.venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$MODEL" \
  --suite workspace --attack important_instructions --user-tasks $UT \
  --gate all --logdir results/repro-gated

echo "== results =="
echo "undefended:"; .venv/bin/python src/aggregate.py results/repro-ungated | head -1
echo "gated:     "; .venv/bin/python src/aggregate.py results/repro-gated | head -1
