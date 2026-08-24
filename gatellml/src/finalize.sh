#!/usr/bin/env bash
# Finalizer: fires when Addenda E+E2 complete, then assembles the publication
# dataset automatically: full summary -> FINAL_SUMMARY.md -> STATE log -> commit.
set -u
REPO=/home/dafarus/vault/projects/gatellml
R="$REPO/gatellml/results"
LOCK="$R/.campaign.lock"

while [ -e "$LOCK" ] || pgrep -f "[r]un_defended" >/dev/null || \
      ! grep -q "ADDENDUM E COMPLETE" "$R/addendum_e.log" 2>/dev/null || \
      ! grep -q "ADDENDUM E2 COMPLETE" "$R/addendum_e2.log" 2>/dev/null; do
  sleep 120
done

cd "$REPO"
{
  echo "# FINAL SUMMARY — gatellml overnight campaigns ($(date '+%Y-%m-%d %H:%M'))"
  echo
  echo "## All arms"
  echo '```'
  .venv/bin/python gatellml/src/suite_summary.py 2>/dev/null | grep -vE "^c[12]-|smoke"
  echo '```'
  echo
  echo "## Variance packs (k-repeats)"
  echo '```'
  .venv/bin/python gatellml/src/krepeat_summary.py gatellml/results 2>/dev/null
  for d in sk1-gated tk1-gated; do
    n=$(ls -d "$R"/$d-k* 2>/dev/null | wc -l)
    [ "$n" -gt 0 ] && echo "$d: $n repeats on disk"
  done
  echo '```'
} > "$R/FINAL_SUMMARY.md"

cat >> gatellml/STATE.md <<EOF

## FINALIZATION (auto, $(date '+%Y-%m-%d %H:%M'))

All campaigns complete. Full table written to gatellml/results/FINAL_SUMMARY.md.
Local replication arms (Addendum E/E2) are part of the record; paper §5.5 takes its numbers
from FINAL_SUMMARY.md lines l*.
EOF

git add -A
git commit -q -m "finalizer: overnight campaign results assembled (auto)"
echo "$(date) FINALIZED" >> "$R/finalizer.log"
