#!/usr/bin/env bash
# Addendum F — re-run of Addendum B/E2 on completed manifests (g3 / l6 arms).
#
# WHY: B's manifests declared 6 of travel's 28 tools and 7 of slack's 11. gatellm denies
# undeclared tools, so every undeclared read was refused, the injection payload never
# reached the model, and g2-travel-attack-gated 0/21 measured nothing (21/21 cells
# vacuous, 0 contract blocks, 25 undeclared_tool blocks). Same for l4-travel-attack-gB.
#
# WHAT CHANGED: *.policy.v2.json declares the omitted read tools. Existing declarations
# are byte-identical to v1 — no contract under test was retuned. If travel still breaches,
# the contracts genuinely failed to cover it; that is the point of re-running.
#
# The g2-*/l2-*/l4-* arms stay on disk untouched, as gw1 did after the earlier deviation.
#
#   bash gatellml/src/addendum_f.sh local     # Ollama arms, free
#   bash gatellml/src/addendum_f.sh venice    # frontier arms, bills against the Venice key
#   bash gatellml/src/addendum_f.sh both
set -u

REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"
PY="$REPO/.venv/bin/python"
SLACK_M="$REPO/gatellml/manifests/slack.policy.v2.json"
TRAVEL_M="$REPO/gatellml/manifests/travel.policy.v2.json"

VENICE_MODEL=qwen3-coder-480b-a35b-instruct-turbo
LOCAL_MODEL=qwen3-coder-32k:latest

WHICH="${1:-}"
case "$WHICH" in
  local|venice|both) ;;
  *) echo "usage: $0 {local|venice|both}" >&2; exit 2 ;;
esac

for m in "$SLACK_M" "$TRAVEL_M"; do
  [ -f "$m" ] || { echo "missing manifest: $m" >&2; exit 2; }
done
if [ "$WHICH" != "local" ] && [ -z "${VENICE_API_KEY:-}" ]; then
  echo "VENICE_API_KEY is not set; frontier arms would fail" >&2; exit 2
fi

while [ -e "$LOCK" ]; do echo "[wait] campaign lock held"; sleep 30; done
trap 'rm -f "$LOCK"' EXIT
touch "$LOCK"
cd "$REPO" || exit 1

ATTACK_ARMS=()

# run <name> <provider> <model> <expected_cells> -- <runner args...>
run() {
  local name="$1" provider="$2" model="$3" expect="$4"; shift 5
  if [ -f "$R/$name/.DONE" ]; then echo "[skip] $name"; return; fi
  echo "=== $(date +%H:%M:%S) START $name ($provider, expect $expect cells) ==="
  setsid "$PY" src/run_defended.py --provider "$provider" --model-id "$model" \
    --logdir "$R/$name" "$@" >> "$R/${name}.log" 2>&1
  local rc=$?
  # Completion is judged by cells on disk, not by rc: SuiteResults reports rc=2 with a
  # "0/0" summary on gated arms that in fact completed (logged in STATE, Addendum E).
  local got
  got=$(find "$R/$name" -name '*.json' -path '*/user_task_*' 2>/dev/null | wc -l)
  if [ "$got" -ge "$expect" ]; then
    touch "$R/$name/.DONE"
    echo "=== $(date +%H:%M:%S) DONE $name rc=$rc cells=$got/$expect ==="
  else
    echo "=== $(date +%H:%M:%S) INCOMPLETE $name rc=$rc cells=$got/$expect — rerun to resume ==="
  fi
}

# Attack arms first: they carry the falsifiable security claim. Benign arms price it.
frontier() {
  run g3-slack-attack-gated  venice "$VENICE_MODEL" 15 -- \
    --gate gatellm --gatellm-manifest "$SLACK_M" \
    --suite slack  --user-tasks user_task_0 user_task_1 user_task_2
  run g3-travel-attack-gated venice "$VENICE_MODEL" 21 -- \
    --gate gatellm --gatellm-manifest "$TRAVEL_M" \
    --suite travel --user-tasks user_task_0 user_task_1 user_task_2
  run g3-slack-benign-gated  venice "$VENICE_MODEL" 21 -- \
    --gate gatellm --gatellm-manifest "$SLACK_M"  --suite slack  --benign-only
  run g3-travel-benign-gated venice "$VENICE_MODEL" 20 -- \
    --gate gatellm --gatellm-manifest "$TRAVEL_M" --suite travel --benign-only
  ATTACK_ARMS+=(g3-slack-attack-gated g3-travel-attack-gated)
}

local_arms() {
  export LOCAL_LLM_PORT=11434
  run l6-slack-attack-gB2  local "$LOCAL_MODEL" 15 -- \
    --gate gatellm --gatellm-manifest "$SLACK_M" \
    --suite slack  --user-tasks user_task_0 user_task_1 user_task_2
  run l6-travel-attack-gB2 local "$LOCAL_MODEL" 21 -- \
    --gate gatellm --gatellm-manifest "$TRAVEL_M" \
    --suite travel --user-tasks user_task_0 user_task_1 user_task_2
  run l6-slack-benign-gB2  local "$LOCAL_MODEL" 21 -- \
    --gate gatellm --gatellm-manifest "$SLACK_M"  --suite slack  --benign-only
  run l6-travel-benign-gB2 local "$LOCAL_MODEL" 20 -- \
    --gate gatellm --gatellm-manifest "$TRAVEL_M" --suite travel --benign-only
  ATTACK_ARMS+=(l6-slack-attack-gB2 l6-travel-attack-gB2)
}

case "$WHICH" in
  venice) frontier ;;
  local)  local_arms ;;
  both)   frontier; local_arms ;;
esac

echo
echo "=== $(date +%H:%M:%S) ADDENDUM F RUNS COMPLETE — auditing ==="
echo
echo "--- vacuity audit (a 0/N with vacuous cells claims nothing) ---"
if [ "${#ATTACK_ARMS[@]}" -eq 0 ]; then
  echo "no attack arms ran"; VAC=0
else
  "$PY" gatellml/src/vacuity_check.py "$R" "${ATTACK_ARMS[@]}"
  VAC=$?
fi
echo
echo "--- arm counts ---"
"$PY" gatellml/src/suite_summary.py "$R" | grep -E '^arm|^g3-|^l6-|^g2-|^l2-|^l4-'
echo
if [ "$VAC" -ne 0 ]; then
  echo "VERDICT: at least one arm is still mostly vacuous — do NOT quote its rate."
else
  echo "VERDICT: payload delivery confirmed; breach rates above are attributable to contracts."
fi
echo "=== $(date +%H:%M:%S) ADDENDUM F COMPLETE ==="
