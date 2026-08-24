#!/usr/bin/env bash
# One-command progress view for the gatellml campaigns.
# Usage:  bash ~/vault/projects/gatellml/gatellml/src/status.sh
# Auto-refreshing:  watch -n 30 bash ~/vault/projects/gatellml/gatellml/src/status.sh
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"

echo "== $(date '+%H:%M:%S') =="
echo "-- runner alive:"
pgrep -af "[r]un_defended" | sed 's/ --logdir/ ->/' | sed 's/^/   /' || echo "   (none — fleet idle/done)"
echo "-- latest events:"
for f in "$R"/addendum_*.log "$R"/campaign.log; do
  [ -f "$f" ] && tail -1 "$f" | sed "s|^|   $(basename $f .log): |"
done
echo "-- arms (attack=breach count, benign_utility, blocks):"
cd "$REPO"
.venv/bin/python gatellml/src/suite_summary.py 2>/dev/null | grep -vE "^c[12]-|smoke"
echo "-- last commit:"
git log --oneline -1
