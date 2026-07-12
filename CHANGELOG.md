# Changelog

## 0.2.0 — 2026-07-12

A hardening release: two data-loss/lockout bugs fixed, plus security, Windows,
and UX fixes from a full audit. No config changes needed to upgrade — replace
`remora.py` and restart.

### Security
- Session cookie is marked `Secure` only when the request actually arrived over
  TLS (`X-Forwarded-Proto: https`). Previously it was set on plain HTTP for any
  non-localhost host, which made browsers drop it — locking LAN and Docker users
  (`http://192.168.x.x`) out of login. Still `Secure` behind a TLS proxy.
- The state file (`remora.json`: password hash + session secret) can no longer
  be read through the file editor on case-insensitive filesystems (Windows,
  macOS) via `REMORA.JSON`.
- POST bodies are drained before an early `403`/`413`, so a rejected request no
  longer corrupts the keep-alive stream.

### Data integrity
- **Autosave is no longer left off forever** when a scheduled backup hits the
  disk-space guard. The old liveness probe (`save-off`) disabled world saving
  and an early return skipped the `save-on` — a crash in that window lost world
  progress. The probe is now `list`.
- Symlinked world directories are dereferenced into the archive. They were
  previously stored as a bare symlink entry — a `0 MB, done` backup with no
  world data.
- A backup that fails mid-archive (a file vanishing during `tar`) is deleted
  instead of leaving a corrupt-but-valid-looking `.tgz` that displaces a good
  backup at prune.

### Reliability
- The generated first-run admin password is no longer swallowed by block-
  buffered stdout under systemd (which locked new installs out with no password
  anywhere).
- Two background threads that could die silently are fixed: the RCON path on a
  lone-surrogate command (which also killed the scheduler), and the log-tail on
  a rotation race.
- Concurrent saves of the same file no longer crash (shared temp-file name).
- File downloads close the connection on a short read instead of desyncing
  keep-alive when the file shrinks mid-stream.

### Windows / portability
- A missing `/proc` no longer kills the metrics thread. remora runs on Windows;
  only the memory tile stays empty.
- All text I/O is explicit UTF-8, fixing mojibake of chat history and editor
  crashes on non-UTF-8 Windows codepages.

### UX
- Console: command history (↑/↓); the tab now follows the newest line on open.
- Whitelist: Enter adds a player.
- Expired-session tabs redirect to login instead of looping `/events` forever.
- Clearer diagnostics for RCON auth mismatch and misconfigured startup.
- Correct player name extracted from classic-vanilla whitelist-rejection logs
  (was capturing the `GameProfile@hash` toString).

### Docs
- New "Where it runs" section: same-machine requirement and a
  Windows/Docker/managed-hosting support matrix.
- systemd unit example includes `User=`.

### Tests
- End-to-end auth-boundary coverage and the first real backup-pipeline test.

## 0.1.0

Initial release.
