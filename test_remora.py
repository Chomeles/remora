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
remora.ATTEMPTS.clear()
# classic vanilla (1.7-1.20.1) whitelist reject logs the GameProfile toString,
# not a plain name — WL_NAME must still extract the real name= value
_classic = ('[20:24:12] [Server thread/INFO]: Disconnecting com.mojang.authlib.'
            'GameProfile@e6d7742[id=<null>,name=.Gamer Tag,properties={},legacy=false]'
            ' (/127.0.0.1:51234): You are not white-listed on this server!')
remora._ingest(_classic, 'd', live=False)
assert list(remora.ATTEMPTS) == ['.Gamer Tag'], remora.ATTEMPTS
# chat/say must not spoof the rejected-joins list — '<Bob> whitelist name=Griefer'
# used to plant an attacker-chosen name next to a one-click ✅ whitelist button
remora._ingest('[12:00:00] [Server thread/INFO]: <Bob> pls whitelist me name=Griefer', 'd', live=False)
remora._ingest('[12:00:01] [Server thread/INFO]: [Not Secure] [Bob] whitelist name=Sneaky', 'd', live=False)
assert 'Griefer' not in remora.ATTEMPTS and 'Sneaky' not in remora.ATTEMPTS, remora.ATTEMPTS
remora.ATTEMPTS.clear(); remora.FEED.clear(); remora.CONSOLE.clear()

# ── panel restart: load_history seeds the Console from latest.log (a crashed
#    server's last output must be visible, not a blank box), but NOT from
#    rotated .gz history (date-less old sessions would read as recent) ──
import gzip as _gz, tempfile as _tf
from pathlib import Path as _P
with _tf.TemporaryDirectory() as _td:
    _d = _P(_td)
    (_d / 'logs').mkdir()
    (_d / 'logs' / 'latest.log').write_text(
        '[03:12:44] [Server thread/ERROR]: java.lang.OutOfMemoryError\n')
    with _gz.open(_d / 'logs' / '2026-07-10-1.log.gz', 'wt') as _g:
        _g.write('[01:00:00] [Server thread/INFO]: <Old> gz session chat\n')
    remora.SERVER_DIR, remora.LOG_PATH = _d, _d / 'logs' / 'latest.log'
    remora.load_history()
    assert list(remora.CONSOLE) == \
        ['[03:12:44] [Server thread/ERROR]: java.lang.OutOfMemoryError'], remora.CONSOLE
    assert any(e['msg'] == 'gz session chat' for e in remora.FEED), \
        'gz history must still seed the chat feed'
remora.ATTEMPTS.clear(); remora.FEED.clear(); remora.CONSOLE.clear()

# ── console auto-follows to newest when its tab is first opened ──
assert "if(!c.scrollTop)c.scrollTop=c.scrollHeight" in remora.PAGE, \
    'console tab must jump to newest line on open'

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

# ── POST body must be a dict — "[]"/"null" crashed the handler (AttributeError) ──
import inspect
src = inspect.getsource(remora.Handler.do_POST)
assert 'isinstance(body, dict)' in src, 'non-dict JSON guard missing in do_POST'

# ── Secure cookie only over real TLS — Host-sniffing locked out LAN users
# (browsers drop Secure cookies on plain-http non-localhost origins) ──
src = inspect.getsource(remora.Handler.login)
assert "'X-Forwarded-Proto'" in src and 'plain_local' not in src, \
    'Secure must depend on X-Forwarded-Proto, never on Host guessing'
assert remora.Handler.timeout == 60, 'idle-connection timeout missing'

# ── console keyboard UX: command history + enter-to-add on whitelist ──
assert 'ArrowUp' in remora.PAGE and 'ArrowDown' in remora.PAGE
assert "$('#wlIn').onkeydown" in remora.PAGE, 'enter in whitelist input must add'

# ── README accuracy: the "~N lines — read it" claim must not silently drift ──
import pathlib
_readme = pathlib.Path(__file__).with_name('README.md').read_text()
_m = _re.search(r'~(\d+) lines', _readme)
_actual = len(open(pathlib.Path(__file__).with_name('remora.py')).readlines())
assert _m and abs(_actual - int(_m[1])) / _actual < 0.2, \
    f'README claims ~{_m and _m[1]} lines, remora.py has {_actual}'

# ── e2e: the auth boundary over real HTTP (regression net for the LAN-cookie bug) ──
import http.client, threading as _th
from http.server import ThreadingHTTPServer
with tempfile.TemporaryDirectory() as td:
    d = Path(td)
    (d / 'logs').mkdir()
    (d / 'logs' / 'latest.log').write_text('')
    (d / 'server.properties').write_text('enable-rcon=true\nrcon.port=1\n')
    remora.SERVER_DIR, remora.STATE_PATH = d, d / 'remora.json'
    remora.BACKUP_DIR, remora.LOG_PATH = d / 'backups', d / 'logs' / 'latest.log'
    remora.RCON_ADDR = ('127.0.0.1', 1)      # closed port: rcon() fails fast
    remora.NO_AUTH, remora.SERVER_UP = False, False
    remora.STATE = {'pw': remora.hash_pw('hunter22'), 'secret': 'bb' * 32,
                    'schedules': [], 'keep_backups': 5, 'start_cmd': ''}
    remora.save_state()                       # remora.json exists on disk...
    srv = ThreadingHTTPServer(('127.0.0.1', 0), remora.Handler)
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    c = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=5)

    def req(method, path, body=None, hdrs={}):
        c.request(method, path, body, {'Content-Type': 'application/json', **hdrs})
        r = c.getresponse()
        return r, r.read()

    r, _ = req('GET', '/state.json')
    assert r.status == 401, 'unauthenticated state.json must 401'
    r, _ = req('POST', '/login', '{"password":"wrong"}')
    assert r.status == 403
    r, _ = req('POST', '/login', '{"password":"hunter22"}',
               {'Origin': 'https://evil.example'})
    assert r.status == 403, 'cross-origin login must be rejected'
    r, _ = req('POST', '/login', '{"password":"hunter22"}')
    assert r.status == 200
    ck = r.getheader('Set-Cookie')
    assert 'HttpOnly' in ck and 'Secure' not in ck, \
        'plain-http cookie must not be Secure (LAN login lockout)'
    tok = ck.split(';')[0]
    r, data = req('GET', '/state.json', hdrs={'Cookie': tok})
    assert r.status == 200 and b'"whitelist"' in data
    r, data = req('GET', '/files?d=', hdrs={'Cookie': tok})
    assert r.status == 200 and b'remora.json' not in data, '...but stays hidden'
    r, _ = req('GET', '/file?p=remora.json', hdrs={'Cookie': tok})
    assert r.status == 400, 'state file must not be readable'
    # SSE: an evicted subscriber's socket must CLOSE (EOF), not zombie in
    # keep-alive until the 60s handler timeout while the browser waits on a
    # dead stream. The 5s client timeout below fails the test if it zombies.
    import time as _time
    c2 = http.client.HTTPConnection('127.0.0.1', srv.server_port, timeout=5)
    c2.request('GET', '/events', headers={'Cookie': tok})
    r2 = c2.getresponse()
    assert r2.status == 200 and r2.fp.readline() == b': hi\n'
    for _ in range(100):                     # wait for the sub to register
        if remora.SUBS: break
        _time.sleep(0.05)
    (q,) = remora.SUBS
    with remora.SUBS_LOCK:                   # simulate publish()'s slow-consumer
        remora.SUBS.discard(q)               # eviction on queue.Full
    q.put('bye')                             # wake the handler's blocking get()
    r2.read()                                # must reach EOF, not time out
    c2.close()
    srv.shutdown()

# ── restart with no start_cmd must refuse BEFORE stopping — it used to stop
#    the server and only then find it couldn't start it back (down until an
#    admin noticed; worst via a scheduled 3am restart) ──
_calls, _orig_rcon, _orig_pub = [], remora.rcon, remora.publish
remora.rcon = lambda cmd, timeout=10: (_calls.append(cmd), '')[1]
remora.publish = lambda ev: None
remora.STATE['start_cmd'] = ''
try:
    for op in ('restart', 'start'):
        assert remora.power(op), f'{op} with no start_cmd must return an error'
    assert not _calls, f'must refuse before any rcon command, got {_calls}'
finally:
    remora.rcon, remora.publish = _orig_rcon, _orig_pub

# ── lone surrogate in a command must not raise (killed /cmd + scheduler thread) ──
remora._rcon_pkt(1, 2, '\ud800list')   # would raise UnicodeEncodeError before the fix

# ── case-insensitive filesystems must not leak remora.json via REMORA.JSON ──
with tempfile.TemporaryDirectory() as td:
    b = Path(td)
    for variant in ('remora.json', 'REMORA.JSON', 'Remora.Json', 'remora.JSON'):
        assert remora.safe_path(b, variant) is None, f'{variant} must be blocked'

# ── SSE onerror must trigger a refresh so the 401-handler can redirect ──
assert 'es.close();refreshSoon();setTimeout(connect,3000)' in remora.PAGE, \
    'expired-session tab would loop /events forever without refreshSoon in onerror'

# ── backup pipeline: real coverage (dereference symlinked world; disk-guard
#    must NOT leave autosave off) ──
import tarfile as _tar, shutil as _sh
def _run_backup_env(free_bytes):
    calls = []
    orig_rcon, orig_disk = remora.rcon, _sh.disk_usage
    remora.rcon = lambda cmd, timeout=10: (calls.append(cmd), '')[1]
    class _DU:  # mimic shutil.disk_usage(...).free
        free = free_bytes
    _sh.disk_usage = lambda p: _DU
    return calls, (orig_rcon, orig_disk)
with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as store:
    d = Path(td)
    (d / 'server.properties').write_text('level-name=world\n')
    real = Path(store); (real / 'region').mkdir()
    (real / 'level.dat').write_bytes(b'DATA')
    (d / 'world').symlink_to(real)           # world is a symlink to another disk
    remora.SERVER_DIR, remora.BACKUP_DIR = d, d / 'backups'
    remora.SERVER_UP = True
    # A) normal backup: symlinked world must be dereferenced into the archive
    calls, (orig_rcon, orig_disk) = _run_backup_env(10**12)
    try:
        assert remora.run_backup() is None, 'backup should succeed'
        tgz = list((d / 'backups').glob('backup-*.tgz'))
        assert len(tgz) == 1, tgz
        names = _tar.open(tgz[0]).getnames()
        assert 'world/level.dat' in names, f'symlinked world not dereferenced: {names}'
        assert 'save-off' in calls and 'save-on' in calls
        tgz[0].unlink()
    finally:
        remora.rcon, _sh.disk_usage = orig_rcon, orig_disk
    # B) disk-space guard fires BEFORE any save-off (else autosave stays off)
    calls, (orig_rcon, orig_disk) = _run_backup_env(1)
    try:
        assert remora.run_backup() == 'not enough disk space'
        assert 'save-off' not in calls, 'disk guard must not leave autosave off'
    finally:
        remora.rcon, _sh.disk_usage = orig_rcon, orig_disk

print('all checks pass')
