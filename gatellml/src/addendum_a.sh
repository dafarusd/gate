#!/usr/bin/env bash
# Addendum A arms: gatellm measurement. Waits for main campaign lock, then runs.
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"
PY="$REPO/.venv/bin/python"
RUNNER="$REPO/src/run_defended.py"
MODEL=qwen3-coder-480b-a35b-instruct-turbo
TASKS10="user_task_0 user_task_1 user_task_2 user_task_3 user_task_4 user_task_5 user_task_6 user_task_7 user_task_8 user_task_9"

while [ -e "$LOCK" ]; do sleep 60; done
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"
cd "$REPO"

run() {
  local name="$1"; shift
  if [ -f "$R/$name/.DONE" ]; then echo "[skip] $name"; return; fi
  echo "=== $(date +%H:%M:%S) START $name ==="
  setsid "$PY" "$RUNNER" --provider venice --model-id "$MODEL" \
    --logdir "$R/$name" "$@" >> "$R/${name}.log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then touch "$R/$name/.DONE"; else echo "=== $name FAILED rc=$rc ==="; fi
  echo "=== $(date +%H:%M:%S) DONE $name rc=$rc ==="
}

run gw1-benign-gatellm --suite workspace --gate gatellm --benign-only --user-tasks $TASKS10

run gw2-attack-gatellm --suite workspace --gate gatellm --user-tasks $TASKS10

for SUITE in banking travel slack; do
  run "g-${SUITE}-benign-gated"   --suite "$SUITE" --gate gatellm --benign-only
  run "g-${SUITE}-benign-ungated" --suite "$SUITE" --gate none --benign-only
done
run g-banking-attack-gated   --suite banking --gate gatellm --user-tasks user_task_0 user_task_1 user_task_2
run g-travel-attack-gated    --suite travel  --gate gatellm --user-tasks user_task_0 user_task_1 user_task_2
run g-slack-attack-gated     --suite slack   --gate gatellm --user-tasks user_task_0 user_task_1 user_task_2

echo "=== $(date +%H:%M:%S) ADDENDUM A COMPLETE ==="
