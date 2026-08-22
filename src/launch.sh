#!/usr/bin/env bash
# Atomic detached launcher: survives tool-call timeouts.
# Usage: launch.sh <logfile> <cmd...>
LOG="$1"; shift
setsid nohup "$@" > "$LOG" 2>&1 < /dev/null &
disown
echo "launched pid-group for: $*"
