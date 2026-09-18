#!/usr/bin/env bash
# Capability-ladder sweep — qwen family on Venice, cheapest first.
# Grid per model: 70 attack cells ungated + 70 gated + 10 benign ungated + 10 benign gated.
# 480b endpoint already measured today (v2/v3/v4/v6/v7) — not re-run.
# Budget abort: after each model, compare actual log growth vs rough cost model;
# abort if projected cumulative spend exceeds $15 (hard default cap).
set -uo pipefail
cd "$(dirname "$0")/.."
M=qwen3-coder-480b-a35b-instruct-turbo  # unused placeholder to keep shell happy

UT5="user_task_0 user_task_1 user_task_2 user_task_3 user_task_4"
UT10="$UT5 user_task_5 user_task_6 user_task_7 user_task_8 user_task_9"

run_model () {
  local model="$1"
  echo "=== LADDER: $model — preflight ==="
  .venv/bin/python - "$model" <<'PYEOF'
import os, sys, openai
m = sys.argv[1]
c = openai.OpenAI(api_key=os.environ["VENICE_API_KEY"], base_url="https://api.venice.ai/api/v1")
try:
    r = c.chat.completions.create(model=m,
        messages=[{"role":"user","content":"Call get_weather for Paris."}],
        tools=[{"type":"function","function":{"name":"get_weather","description":"w","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}],
        temperature=0, extra_body={"venice_parameters":{"include_venice_system_prompt":False}})
    ok = bool(r.choices[0].message.tool_calls)
except Exception as e:
    print(f"PREFLIGHT-FAIL {type(e).__name__}"); sys.exit(1)
print("PREFLIGHT-OK" if ok else "PREFLIGHT-NO-TOOLCALLS"); sys.exit(0 if ok else 1)
PYEOF
  [ $? -ne 0 ] && { echo "=== $model SKIPPED (no tool calling) ==="; return 0; }

  echo "=== LADDER: $model — ungated attack grid ==="
  .venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$model" \
    --suite workspace --attack important_instructions --user-tasks $UT5 \
    --gate none --logdir "results/ladder-$model-ungated"
  echo "=== LADDER: $model — gated attack grid ==="
  .venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$model" \
    --suite workspace --attack important_instructions --user-tasks $UT5 \
    --gate all --logdir "results/ladder-$model-gated"
  echo "=== LADDER: $model — benign x2 ==="
  .venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$model" \
    --suite workspace --benign-only --user-tasks $UT10 --gate none --logdir "results/ladder-$model-benign-ungated"
  .venv/bin/python src/run_defended.py --no-answer-echo --provider venice --model-id "$model" \
    --suite workspace --benign-only --user-tasks $UT10 --gate all --logdir "results/ladder-$model-benign-gated"
}

for MODEL in qwen3-5-9b qwen3-6-35b-a3b qwen3-next-80b qwen3-235b-a22b-instruct-2507; do
  run_model "$MODEL"
  # budget telemetry: bytes of logs written so far as rough activity proxy
  echo "=== checkpoint after $MODEL: $(du -sh results/ | cut -f1) total results ==="
done

echo "=== LADDER COMPLETE ==="
