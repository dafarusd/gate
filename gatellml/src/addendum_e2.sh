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
  echo "=== $(date +%H:%M:%S) DONE $name rc=$rc ==="
}

run l2-slack-attack-gB --gate gatellm --gatellm-manifest "$REPO/gatellml/manifests/slack.policy.json" \
  --suite slack --user-tasks user_task_0 user_task_1 user_task_2

run l4-travel-attack-gB --gate gatellm --gatellm-manifest "$REPO/gatellml/manifests/travel.policy.json" \
  --suite travel --user-tasks user_task_0 user_task_1 user_task_2

run l1-slack-benign-gB --gate gatellm --gatellm-manifest "$REPO/gatellml/manifests/slack.policy.json" \
  --suite slack --benign-only

run l3-travel-benign-gB --gate gatellm --gatellm-manifest "$REPO/gatellml/manifests/travel.policy.json" \
  --suite travel --benign-only

echo "=== $(date +%H:%M:%S) ADDENDUM E2 COMPLETE ==="
