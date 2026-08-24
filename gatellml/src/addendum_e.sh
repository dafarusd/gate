#!/usr/bin/env bash
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"
PY="$REPO/.venv/bin/python"
M=qwen3-coder-32k:latest
export LOCAL_LLM_PORT=11434

while [ -e "$LOCK" ]; do sleep 30; done
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"
cd "$REPO"

run() {
  local name="$1"; shift
  if [ -f "$R/$name/.DONE" ]; then echo "[skip] $name"; return; fi
  echo "=== $(date +%H:%M:%S) START $name ==="
  setsid "$PY" src/run_defended.py --provider local --model-id "$M" \
    --logdir "$R/$name" "$@" >> "$R/${name}.log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then touch "$R/$name/.DONE"; else echo "=== $name FAILED rc=$rc ==="; fi
  echo "=== $(date +%H:%M:%S) DONE $name rc=$rc ==="
}

SL="gatellm --gatellm-manifest"
run l2-slack-attack-ungated --suite slack --gate none --user-tasks user_task_0 user_task_1 user_task_2
run l2-slack-attack-gate    --suite slack --gate all  --user-tasks user_task_0 user_task_1 user_task_2
run l2-slack-attack-gB      --suite slack $SL "$REPO/gatellml/manifests/slack.policy.json" --user-tasks user_task_0 user_task_1 user_task_2

run l4-travel-attack-ungated --suite travel --gate none --user-tasks user_task_0 user_task_1 user_task_2
run l4-travel-attack-gate    --suite travel --gate all  --user-tasks user_task_0 user_task_1 user_task_2
run l4-travel-attack-gB      --suite travel $SL "$REPO/gatellml/manifests/travel.policy.json" --user-tasks user_task_0 user_task_1 user_task_2

run l5-banking-attack-ungated --suite banking --gate none --user-tasks user_task_0 user_task_1 user_task_2
run l5-banking-attack-gate    --suite banking --gate all  --user-tasks user_task_0 user_task_1 user_task_2

run l1-slack-benign-ungated --suite slack --gate none --benign-only
run l1-slack-benign-gate    --suite slack --gate all  --benign-only
run l1-slack-benign-gB      --suite slack $SL "$REPO/gatellml/manifests/slack.policy.json" --benign-only

run l3-travel-benign-ungated --suite travel --gate none --benign-only
run l3-travel-benign-gate    --suite travel --gate all  --benign-only
run l3-travel-benign-gB      --suite travel $SL "$REPO/gatellml/manifests/travel.policy.json" --benign-only

echo "=== $(date +%H:%M:%S) ADDENDUM E COMPLETE ==="
