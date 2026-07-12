#!/usr/bin/env bash
# remora self-improvement loop. Each run: a headless Claude agent makes ONE
# high-value improvement to remora.py, then this script HARD-ENFORCES that the
# result compiles, passes tests, and the live service stays up — otherwise it
# rolls the repo back to the last good commit. The agent is advisory; the guard
# is the real safety net. Wired via cron; safe to run by hand.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="/root/.local/bin:$PATH"

exec 9>/tmp/remora-improve.lock
flock -n 9 || { echo "already running"; exit 0; }

LOG_DIR=logs-improve
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y-%m-%d_%H%M)"
LOG="$LOG_DIR/improve_$STAMP.log"
GOOD="$(git rev-parse HEAD)"

# Guard: repo must be green BEFORE we let an agent touch it.
green() { python3 -m py_compile remora.py && python3 test_remora.py >/dev/null 2>&1; }
if ! green; then
  echo "repo already red at $GOOD — aborting, needs a human" | tee -a "$LOG"
  exit 1
fi

PROMPT='You maintain remora.py, a single-file zero-dependency Python web panel for
Minecraft servers (see README.md). Make exactly ONE worthwhile improvement this run,
then stop.

Rules — non-negotiable:
- Stay single-file (remora.py), Python 3.11+ standard library ONLY. No new files
  except edits to test_remora.py / README.md. No third-party dependencies, ever.
- Be lazy (ponytail): prefer deleting or simplifying over adding. Add a feature only
  if it is clearly valuable to a server admin and cheap. No speculative abstractions.
- Any non-trivial logic you touch keeps a runnable check in test_remora.py.
- You MUST end with: python3 -m py_compile remora.py AND python3 test_remora.py both
  passing. Then commit with git (concise message, prefix "auto:"). If after honest
  effort there is nothing worth changing, make NO commit and say so — do not invent
  busywork.
- Do NOT touch: remora.json, the systemd unit, Caddy, or anything outside this repo.
  Do NOT run destructive git commands (reset --hard, push, rebase). Do NOT restart
  services — the wrapper handles that.

Pick from: correctness bugs, security hardening, UX/accessibility of the embedded UI,
docs accuracy, test coverage, or a small high-value feature. Look at recent git log to
avoid repeating past work. One improvement, verified, committed. Go.'

echo "=== remora-improve $STAMP (from $GOOD) ===" | tee -a "$LOG"
timeout 1800 claude -p "$PROMPT" --dangerously-skip-permissions >>"$LOG" 2>&1
echo "--- agent done, verifying ---" | tee -a "$LOG"

NEW="$(git rev-parse HEAD)"
if [ "$NEW" = "$GOOD" ]; then
  echo "no commit made this run" | tee -a "$LOG"
  git checkout -- . 2>/dev/null; git clean -fd 2>/dev/null   # drop any stray edits
elif green; then
  echo "green at $NEW — restarting service" | tee -a "$LOG"
  systemctl restart mc-remora
  sleep 3
  if systemctl is-active --quiet mc-remora && \
     curl -sf -o /dev/null http://127.0.0.1:3115/login; then
    echo "service healthy after $NEW" | tee -a "$LOG"
    # wrapper (not the agent) syncs the green result to the public GitHub copy
    cp remora.py test_remora.py README.md /root/mc-admin/
    if ! git -C /root/mc-admin diff --quiet; then
      git -C /root/mc-admin add -A
      git -C /root/mc-admin commit -m "$(git log -1 --format=%s)" >>"$LOG" 2>&1
      git -C /root/mc-admin push >>"$LOG" 2>&1 || echo "github push FAILED" | tee -a "$LOG"
    fi
  else
    echo "service UNHEALTHY after $NEW — rolling back to $GOOD" | tee -a "$LOG"
    git reset --hard "$GOOD"; systemctl restart mc-remora
  fi
else
  echo "commit $NEW is RED — rolling back to $GOOD" | tee -a "$LOG"
  git reset --hard "$GOOD"; systemctl restart mc-remora
fi

ls -1t "$LOG_DIR"/improve_*.log | tail -n +31 | xargs -r rm -f
echo "=== done $(date +%H:%M:%S) ===" | tee -a "$LOG"
