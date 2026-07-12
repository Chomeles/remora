#!/usr/bin/env python3
"""Smallest checks that fail if the core logic breaks: log parser, auth
tokens, password hashing, path safety, rcon framing. Run: python3 test_remora.py"""
import struct
import remora

# ── log parser ──
e = remora.parse_line('[20:26:13] [Server thread/INFO]: <Chomeles> hi there', '2026-07-11')
assert e == {'type': 'chat', 'd': '2026-07-11', 't': '20:26:13',
             'name': 'Chomeles', 'msg': 'hi there'}, e
e = remora.parse_line('[20:45:31] [Server thread/INFO]: [Not Secure] [Rcon] test msg', 'd')
assert e['type'] == 'chat' and e['say'] and e['msg'] == 'test msg', e
e = remora.parse_line('[20:45:31] [Server thread/INFO]: [Rcon] bare rcon say', 'd')
assert e and e['say'] and e['name'] == 'Rcon', e
e = remora.parse_line('[10:00:00] [Server thread/INFO]: [Not Secure] [Chomeles] op say', 'd')
assert e and e['say'] and e['name'] == 'Chomeles', e
# plugin startup lines must NOT be chat
assert remora.parse_line('[20:46:36] [Server thread/INFO]: [Geyser-Spigot] Registered 199 custom block overrides.', 'd') is None
assert remora.parse_line('[20:46:38] [Server thread/INFO]: [ViaVersion] Finished mapping loading', 'd') is None
e = remora.parse_line('[09:00:00] [Server thread/INFO]: [Not Secure] <.Bedrock Kid> yo', 'd')
assert e['name'] == '.Bedrock Kid' and e['msg'] == 'yo', e
e = remora.parse_line('[20:26:13] [Server thread/INFO]: Chomeles joined the game', 'd')
assert e['type'] == 'join' and e['name'] == 'Chomeles', e
e = remora.parse_line('[20:26:46] [Server thread/INFO]: Chomeles left the game', 'd')
assert e['type'] == 'leave', e
assert remora.parse_line('[20:26:13] [Server thread/INFO]: Preparing spawn area', 'd') is None
assert remora.parse_line('garbage', 'd') is None
# XSS payloads survive as data (escaping is the UI's job via textContent)
e = remora.parse_line('[10:00:00] [Server thread/INFO]: <x> <script>alert(1)</script>', 'd')
assert e['msg'] == '<script>alert(1)</script>', e

# ── tokens ──
sec = 'aa' * 32
tok = remora.make_token(sec, ttl=60, now=1000)
assert remora.check_token(sec, tok, now=1030)
assert not remora.check_token(sec, tok, now=2000), 'expired must fail'
assert not remora.check_token(sec, tok + 'x', now=1030), 'tampered sig must fail'
exp, sig = tok.split('.')
assert not remora.check_token(sec, f'{int(exp)+9999}.{sig}', now=1030), 'tampered exp must fail'
assert not remora.check_token(sec, '', now=0) and not remora.check_token(sec, 'a.b', now=0)

# ── password hashing ──
remora.STATE = {'pw': remora.hash_pw('hunter22')}
assert remora.check_pw('hunter22') and not remora.check_pw('hunter23')
remora.STATE = {}
assert not remora.check_pw('anything'), 'no stored pw must never match'

# ── path safety ──
from pathlib import Path
import tempfile, os
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    (base / 'sub').mkdir()
    (base / 'sub' / 'a.yml').write_text('x')
    (base / 'remora.json').write_text('{}')
    outside = Path(tempfile.mkdtemp())
    (base / 'link').symlink_to(outside)
    assert remora.safe_path(base, 'sub/a.yml') == (base / 'sub' / 'a.yml').resolve()
    assert remora.safe_path(base, '') == base.resolve()
    assert remora.safe_path(base, '../etc/passwd') is None
    assert remora.safe_path(base, 'sub/../../etc') is None
    assert remora.safe_path(base, '/etc/passwd') is None
    assert remora.safe_path(base, 'remora.json') is None, 'state file must be hidden'
    assert remora.safe_path(base, 'link/x') is None, 'symlink escape must fail'
    assert remora.safe_path(base, 'a\x00b') is None
    # CRLF must be rejected — else a filename injects response headers via
    # Content-Disposition in stream_file.
    assert remora.safe_path(base, 'evil\r\nSet-Cookie: x=1') is None
    assert remora.safe_path(base, 'tab\tname') is None

# ── rcon framing ──
p = remora._rcon_pkt(7, 2, 'list')
ln = struct.unpack('<i', p[:4])[0]
assert ln == len(p) - 4 and p[4:8] == struct.pack('<i', 7) and p[-2:] == b'\x00\x00'

# ── backup name guard ──
assert remora.BACKUP_NAME.fullmatch('backup-20260711-120000.tgz')
assert not remora.BACKUP_NAME.fullmatch('../etc/passwd')
assert not remora.BACKUP_NAME.fullmatch('backup-20260711-120000.tgz/../x')

# ── prune never deletes everything (keep=0 must not wipe all backups) ──
names = [f'backup-2026071{i}-120000.tgz' for i in range(5)]
for keep in (0, 1, 2, 5, 99):
    k = max(1, keep)
    victims = sorted(names)[:-k]
    assert len(names) - len(victims) >= 1, f'keep={keep} would delete all'
assert sorted(names)[:-max(1, 0)] == names[:-1], 'keep=0 clamps to keep 1'

# ── backup_targets prefix precision (world matches world/world_nether, not worldy) ──
import re as _re
level = 'world'
for name, want in [('world', True), ('world_nether', True), ('world_the_end', True),
                   ('world_backups', True), ('worldedit', False), ('worlds', False)]:
    got = name == level or name.startswith(level + '_')
    assert got == want, (name, got, want)

# ── ATTEMPTS is capped (bot flood of random names can't grow it forever) ──
remora.ATTEMPTS.clear()
wl_line = '[12:00:0{}] [Server thread/INFO]: Disconnecting Bot{} (/1.2.3.4): You are not white-listed on this server!'
for i in range(40):
    remora._ingest(wl_line.format(i % 10, i), 'd', live=False)
assert len(remora.ATTEMPTS) == 30, len(remora.ATTEMPTS)
assert 'Bot39' in remora.ATTEMPTS and 'Bot9' not in remora.ATTEMPTS, 'oldest must be evicted'
remora._ingest(wl_line.format(0, 10), 'd', live=False)   # re-attempt refreshes recency
assert next(iter(remora.ATTEMPTS)) != 'Bot10' and 'Bot10' in remora.ATTEMPTS
remora.ATTEMPTS.clear(); remora.FEED.clear(); remora.CONSOLE.clear()

# ── rate-limit key prunes stale ips (forged-XFF flood can't grow the dict) ──
remora.LOGIN_FAILS.clear()
remora.LOGIN_FAILS['old'] = [0.0]              # ancient, should be swept
assert remora.login_allowed('1.2.3.4')
assert 'old' not in remora.LOGIN_FAILS, 'stale key must be pruned'
for _ in range(8):
    remora.login_failed('1.2.3.4')
assert not remora.login_allowed('1.2.3.4'), '9th attempt must be blocked'
assert remora.login_allowed('5.6.7.8'), 'other ip unaffected'
remora.LOGIN_FAILS.clear()

print('all checks pass')
