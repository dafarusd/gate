#!/usr/bin/env bash
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"
PY="$REPO/.venv/bin/python"
while [ -e "$LOCK" ]; do sleep 60; done
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"
cd "$REPO"
echo "=== $(date +%H:%M:%S) START gw1-full ==="
setsid "$PY" src/run_defended.py --provider venice \
  --model-id qwen3-coder-480b-a35b-instruct-turbo \
  --suite workspace --gate gatellm --benign-only \
  --logdir "$R/gw1-full-benign-gatellm" >> "$R/gw1-full-benign-gatellm.log" 2>&1
rc=$?
[ $rc -eq 0 ] && touch "$R/gw1-full-benign-gatellm/.DONE"
echo "=== $(date +%H:%M:%S) DONE gw1-full rc=$rc ==="
