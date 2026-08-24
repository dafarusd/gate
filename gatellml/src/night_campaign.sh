#!/usr/bin/env bash
# gatellml overnight campaign — pre-registered arms, sequential, resume-safe.
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
RUN="src/run_defended.py"
MODEL=qwen3-coder-480b-a35b-instruct-turbo
R=gatellml/results

run() {
  local name="$1"; shift
  if [ -f "$R/$name/.DONE" ]; then echo "[skip] $name"; return; fi
  echo "=== $(date +%H:%M:%S) START $name ==="
  setsid "$PY" "$RUN" --provider venice --model-id "$MODEL" \
    --logdir "$R/$name" "$@" >> "$R/${name}.log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then touch "$R/$name/.DONE"; else echo "=== $name FAILED rc=$rc (relaunch retries) ==="; fi
  echo "=== $(date +%H:%M:%S) DONE $name rc=$rc ==="
}

mkdir -p "$R"

# banking (16u / 9i)
run b1-benign-gated    --suite banking --gate all --benign-only
run b2-benign-ungated  --suite banking --gate none --benign-only
run b3-attack-gated    --suite banking --gate all \
  --user-tasks user_task_0 user_task_1 user_task_2
run b4-attack-ungated  --suite banking --gate none \
  --user-tasks user_task_0 user_task_1 user_task_2

# travel (20u / 7i)
run t1-benign-gated    --suite travel --gate all --benign-only
run t2-benign-ungated  --suite travel --gate none --benign-only
run t3-attack-gated    --suite travel --gate all \
  --user-tasks user_task_0 user_task_1 user_task_2
run t4-attack-ungated  --suite travel --gate none \
  --user-tasks user_task_0 user_task_1 user_task_2

# slack (21u / 5i)
run s1-benign-gated    --suite slack --gate all --benign-only
run s2-benign-ungated  --suite slack --gate none --benign-only
run s3-attack-gated    --suite slack --gate all \
  --user-tasks user_task_0 user_task_1 user_task_2
run s4-attack-ungated  --suite slack --gate none \
  --user-tasks user_task_0 user_task_1 user_task_2

echo "=== $(date +%H:%M:%S) MAIN CAMPAIGN COMPLETE ==="

# C: workspace variance cell, k-repeats via fresh logdirs per repeat
for i in 01 02 03 04 05 06 07 08 09 10; do
  run c1-gated-r$i   --suite workspace --gate all \
    --user-tasks user_task_2 --injection-tasks injection_task_2
done
for i in 01 02 03 04 05 06 07 08 09 10; do
  run c2-ungated-r$i --suite workspace --gate none \
    --user-tasks user_task_2 --injection-tasks injection_task_2
done

echo "=== $(date +%H:%M:%S) ALL CAMPAIGNS COMPLETE ==="
