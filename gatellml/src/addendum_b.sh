#!/usr/bin/env bash
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"
PY="$REPO/.venv/bin/python"
MODEL=qwen3-coder-480b-a35b-instruct-turbo

while [ -e "$LOCK" ]; do sleep 30; done
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"
cd "$REPO"

run() {
  local name="$1"; shift
  if [ -f "$R/$name/.DONE" ]; then echo "[skip] $name"; return; fi
  echo "=== $(date +%H:%M:%S) START $name ==="
  setsid "$PY" src/run_defended.py --provider venice --model-id "$MODEL" \
    --logdir "$R/$name" "$@" >> "$R/${name}.log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then touch "$R/$name/.DONE"; else echo "=== $name FAILED rc=$rc ==="; fi
  echo "=== $(date +%H:%M:%S) DONE $name rc=$rc ==="
}

M="--gate gatellm --gatellm-manifest"

run g2-slack-benign-gated  --suite slack  $M "$REPO/gatellml/manifests/slack.policy.json"  --benign-only
run g2-slack-attack-gated  --suite slack  $M "$REPO/gatellml/manifests/slack.policy.json"  --user-tasks user_task_0 user_task_1 user_task_2
run g2-travel-benign-gated --suite travel $M "$REPO/gatellml/manifests/travel.policy.json" --benign-only
run g2-travel-attack-gated --suite travel $M "$REPO/gatellml/manifests/travel.policy.json" --user-tasks user_task_0 user_task_1 user_task_2

echo "=== $(date +%H:%M:%S) ADDENDUM B COMPLETE ==="
