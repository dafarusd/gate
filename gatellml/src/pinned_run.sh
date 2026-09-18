#!/usr/bin/env bash
# Run a campaign script from a PINNED copy of the code, never from the tree being edited.
#
#   bash gatellml/src/pinned_run.sh gatellml/src/addendum_j.sh all
#
# Why: each arm of a campaign is its own process and imports the gate at ITS start. Addendum J
# was launched from the working tree while it was still being edited, so its attack arms ran the
# pre-registered commit and its benign arms ran one commit newer. This makes that impossible:
# the code comes from a detached worktree at the commit HEAD names right now, results still land
# in this checkout's results directory, and every arm records the sha it ran.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
[ $# -ge 1 ] || { echo "usage: $0 <script relative to the repo> [args...]" >&2; exit 2; }
SCRIPT="$1"; shift
SHA="$(git -C "$REPO" rev-parse HEAD)"
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no -- gatellml/lang gatellml/manifests src)" ]; then
  echo "[pinned] WARNING: uncommitted changes under gatellml/lang, gatellml/manifests or src are NOT in this run (pinned to ${SHA:0:7})" >&2
fi
PIN="$(dirname "$REPO")/run-${SHA:0:12}"
[ -d "$PIN" ] || git -C "$REPO" worktree add --detach "$PIN" "$SHA" >/dev/null
[ "$(git -C "$PIN" rev-parse HEAD)" = "$SHA" ] || { echo "[pinned] $PIN is not at $SHA" >&2; exit 1; }
echo "[pinned] code: $PIN @ ${SHA:0:12}   results: $REPO/gatellml/results"
export GATELLML_RESULTS="$REPO/gatellml/results" GATELLML_PINNED_SHA="$SHA"
exec bash "$PIN/$SCRIPT" "$@"
