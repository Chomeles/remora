#!/usr/bin/env python3
"""remora — a single-file, zero-dependency web panel for Minecraft servers.

Like the remora fish, it attaches to a big animal instead of being one:
it talks to a RUNNING server via RCON and its log files, and never owns
the java process. Works with systemd, screen, docker — anything.

    python3 remora.py /path/to/server --port 8765

Features: live console + chat (SSE), full chat history across rotated logs,
player/whitelist/ban management, file editor, world backups with pruning,
scheduler, TPS/players/memory sparklines, PBKDF2 session auth.

MIT license. Python 3.11+. No dependencies.
"""
import argparse, gzip, hashlib, hmac, json, os, queue, re, secrets
import shutil, socket, struct, subprocess, sys, tarfile, threading, time
import urllib.parse
from datetime import date, datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = '0.2.0'

# ── globals set by init() ────────────────────────────────────────────────
SERVER_DIR = None      # Path
STATE_PATH = None      # Path
BACKUP_DIR = None      # Path
LOG_PATH = None        # Path
RCON_ADDR = None       # (host, port)
RCON_PW = ''
NO_AUTH = False
STATE = {}             # persisted: pw, secret, schedules, keep_backups, start_cmd
STATE_LOCK = threading.Lock()

# ── persisted state ──────────────────────────────────────────────────────
def load_state():
    global STATE
    try:
        STATE = json.loads(STATE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        STATE = {}
    STATE.setdefault('schedules', [])
    STATE.setdefault('keep_backups', 5)
    STATE.setdefault('start_cmd', '')
    STATE.setdefault('secret', secrets.token_hex(32))
    save_state()

def save_state():
    tmp = STATE_PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(STATE, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(STATE_PATH)

# ── passwords & sessions ─────────────────────────────────────────────────
def hash_pw(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000)
    return {'salt': salt.hex(), 'hash': dk.hex(), 'iter': 200_000}

def check_pw(pw):
    rec = STATE.get('pw')
    if not rec:
        return False
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(rec['salt']),
                             rec['iter'])
    return hmac.compare_digest(dk.hex(), rec['hash'])

def make_token(secret, ttl=7 * 86400, now=None):
    exp = int(now if now is not None else time.time()) + ttl
    sig = hmac.new(bytes.fromhex(secret), str(exp).encode(), 'sha256').hexdigest()
    return f'{exp}.{sig}'

def check_token(secret, tok, now=None):
    try:
        exp, sig = tok.split('.', 1)
        good = hmac.new(bytes.fromhex(secret), exp.encode(), 'sha256').hexdigest()
        return hmac.compare_digest(sig, good) and \
            int(exp) > (now if now is not None else time.time())
    except (ValueError, AttributeError):
        return False

LOGIN_FAILS = {}       # ip -> [timestamps]; in-memory, resets on restart
FAILS_LOCK = threading.Lock()

def login_allowed(ip):
    with FAILS_LOCK:
        now = time.time()
        for k in [k for k, v in LOGIN_FAILS.items()      # drop stale keys so a
                  if all(now - t >= 300 for t in v)]:      # forged-XFF flood can't
            del LOGIN_FAILS[k]                             # grow the dict forever
        LOGIN_FAILS[ip] = [t for t in LOGIN_FAILS.get(ip, []) if now - t < 300]
        return len(LOGIN_FAILS[ip]) < 8

def login_failed(ip):
    with FAILS_LOCK:
        LOGIN_FAILS.setdefault(ip, []).append(time.time())

# ── RCON (minimal client, Source RCON protocol) ──────────────────────────
RCON_LOCK = threading.Lock()
_RCON_AUTH_WARNED = False   # print the auth-mismatch hint once, not every poll

def _rcon_pkt(rid, ptype, body):
    # 'replace': a lone UTF-16 surrogate in a command (valid JSON) would raise
    # UnicodeEncodeError here, which rcon()'s except doesn't catch — that killed
    # the /cmd request and, via a bad schedule action, the scheduler thread.
    p = struct.pack('<ii', rid, ptype) + body.encode('utf-8', 'replace') + b'\x00\x00'
    return struct.pack('<i', len(p)) + p

def _rcon_recv(s):
    raw = b''
    while len(raw) < 4:
        chunk = s.recv(4 - len(raw))
        if not chunk:
            raise OSError('rcon closed')
        raw += chunk
    ln = struct.unpack('<i', raw)[0]
    if ln < 10 or ln > 4_200_000:        # malformed frame (wrong service on port)
        raise OSError('bad rcon frame length')
    d = b''
    while len(d) < ln:
        chunk = s.recv(ln - len(d))
        if not chunk:
            raise OSError('rcon closed')
        d += chunk
    rid, _ptype = struct.unpack('<ii', d[:8])
    return rid, d[8:-2].decode(errors='replace')

def rcon(cmd, timeout=10):
    """Run a command; returns output string, or None if the server is down.
    ponytail: one connection per command — a persistent conn needs reconnect
    logic for every server restart; per-call is slower but always correct."""
    with RCON_LOCK:
        try:
            with socket.create_connection(RCON_ADDR, timeout=timeout) as s:
                s.sendall(_rcon_pkt(1, 3, RCON_PW))
                rid, _ = _rcon_recv(s)
                if rid == -1:                     # auth rejected
                    global _RCON_AUTH_WARNED
                    if not _RCON_AUTH_WARNED:     # once: else it floods on every poll
                        _RCON_AUTH_WARNED = True
                        print('rcon: auth failed — rcon.password in server.properties '
                              'does not match the running server (restart the server '
                              'after editing it)', file=sys.stderr, flush=True)
                    return None
                s.sendall(_rcon_pkt(2, 2, cmd))
                # ponytail: single response packet. Vanilla fragments bodies
                # >4KB; list/whitelist/banlist stay well under. Multi-packet
                # reassembly (dummy-id trailer) if a huge output ever truncates.
                _, body = _rcon_recv(s)
                return re.sub('§.', '', body)
        except (OSError, struct.error):
            return None

def names_after_colon(out):
    if not out or ':' not in out:
        return []
    return [n.strip() for n in out.split(':', 1)[1].split(',') if n.strip()]

# ── log parsing ──────────────────────────────────────────────────────────
# Bedrock (Geyser/Floodgate) names may start with '.' and contain spaces.
TS_INFO = r'^\[(\d\d:\d\d:\d\d)\] \[[^\]]*INFO\]: '
CHAT_RE = re.compile(TS_INFO + r'(?:\[Not Secure\] )?<(.{1,48}?)> (.*)$')
# /say broadcasts carry [Not Secure] (chat signing) or come from [Rcon]/[Server];
# plugin log lines ([Geyser-Spigot] ...) must NOT match.
SAY_RE = re.compile(TS_INFO + r'(?:\[Not Secure\] \[(.{1,48}?)\]|\[(Rcon|Server)\]) (.+)$')
JOIN_RE = re.compile(TS_INFO + r'(.{1,48}?) joined the game$')
LEAVE_RE = re.compile(TS_INFO + r'(.{1,48}?) left the game$')
WL_LINE = re.compile(r'white-?list', re.I)
# Two forms of whitelist-rejection line. Modern (Paper/1.20.2+): 'Disconnecting
# <name> (/ip): ...'. Classic vanilla (1.7–1.20.1): 'Disconnecting
# com.mojang.authlib.GameProfile@hash[...,name=<name>,...] (/ip): ...'. Try
# name= first — re picks the leftmost POSITION, so a single alternation with
# 'Disconnecting ' first always captured the GameProfile toString garbage.
WL_NAME = re.compile(r'name=([^,()\[\]]{1,48})')
WL_NAME2 = re.compile(r'Disconnecting (.{1,48}?) \(/')
DONE_RE = re.compile(TS_INFO + r'Done \(')
STOP_RE = re.compile(TS_INFO + r'Stopping server')

def parse_line(line, day):
    """One log line -> event dict or None. day = 'YYYY-MM-DD'."""
    if m := CHAT_RE.match(line):
        return {'type': 'chat', 'd': day, 't': m[1], 'name': m[2], 'msg': m[3]}
    if m := SAY_RE.match(line):
        return {'type': 'chat', 'd': day, 't': m[1], 'name': m[2] or m[3],
                'msg': m[4], 'say': True}
    if m := JOIN_RE.match(line):
        return {'type': 'join', 'd': day, 't': m[1], 'name': m[2]}
    if m := LEAVE_RE.match(line):
        return {'type': 'leave', 'd': day, 't': m[1], 'name': m[2]}
    return None

# ── in-memory buffers ────────────────────────────────────────────────────
from collections import deque
FEED = deque(maxlen=1000)      # chat/join/leave events, oldest first
CONSOLE = deque(maxlen=400)    # raw log lines
METRICS = deque(maxlen=4320)   # (ts, players, tps, rss_mb, cpu_pct) @20s = 24h
ATTEMPTS = {}                  # name -> 'HH:MM' last whitelist-rejected join, capped 30
ONLINE = []                    # last known online player names
SERVER_UP = None               # None until first probe
BUF_LOCK = threading.Lock()

def load_history():
    """Seed FEED/ATTEMPTS from rotated .log.gz files + latest.log — the whole
    chat history survives panel and server restarts."""
    logs = []
    for p in sorted(SERVER_DIR.glob('logs/*.log.gz')):
        if m := re.match(r'(\d{4}-\d\d-\d\d)-(\d+)\.log\.gz$', p.name):
            logs.append((m[1], int(m[2]), p))
    logs.sort()
    for day, _, p in logs:
        try:
            with gzip.open(p, 'rt', encoding='utf-8', errors='replace') as f:
                for line in f:
                    _ingest(line, day, live=False)
        except OSError:
            pass
    try:
        day = date.fromtimestamp(LOG_PATH.stat().st_mtime).isoformat()
        for line in open(LOG_PATH, encoding='utf-8', errors='replace'):
            _ingest(line, day, live=False, seed_console=True)
    except OSError:
        pass

def _ingest(line, day, live=True, seed_console=False):
    line = line.rstrip('\n')
    if not line:
        return
    ev = parse_line(line, day)
    with BUF_LOCK:
        # seed_console: load_history replays latest.log into CONSOLE so a
        # panel restart shows the current session's output (e.g. last night's
        # crash) instead of a blank box. Rotated .gz history stays out — its
        # date-less HH:MM:SS lines would pass off old sessions as recent.
        if live or seed_console:
            CONSOLE.append(line)
        if ev:
            FEED.append(ev)
        # ev is None: a chat line '<Bob> whitelist me name=Griefer' matches the
        # scrapers below and planted an attacker-chosen name in the panel's
        # rejected-joins list — next to a one-click whitelist button. Real
        # rejection lines never parse as chat/join/leave events.
        if ev is None and WL_LINE.search(line) and 'INFO' in line:
            if m := (WL_NAME.search(line) or WL_NAME2.search(line)):
                # bounded: bots probing random names must not grow this forever;
                # pop-then-set keeps insertion order = recency, evict oldest.
                ATTEMPTS.pop(m[1], None)
                ATTEMPTS[m[1]] = line[1:9] if line[:1] == '[' else '?'
                while len(ATTEMPTS) > 30:
                    del ATTEMPTS[next(iter(ATTEMPTS))]
    if live:
        publish({'type': 'log', 'line': line})
        if ev:
            publish(ev)
        if DONE_RE.match(line):
            set_status(True)
        elif STOP_RE.match(line):
            set_status(False)

def tail_loop():
    f, ino = None, None
    first = True
    frag = ''                    # partial line held back until its newline
    while True:
        try:
            st = os.stat(LOG_PATH)
            # reopen on inode change OR in-place truncation (copytruncate,
            # `> latest.log`) — both leave our offset stale otherwise.
            if f is None or st.st_ino != ino or st.st_size < f.tell():
                if f:
                    f.close()
                    f = None   # a failed reopen must not leave a closed-but-
                               # not-None f; next iter's f.tell() would raise
                               # ValueError and kill the tail thread for good.
                f = open(LOG_PATH, encoding='utf-8', errors='replace')
                ino = st.st_ino
                frag = ''
                if first:            # backlog already loaded by load_history
                    f.seek(0, 2)
                first = False
            chunk = f.readline()
            if chunk:
                frag += chunk
                if frag.endswith('\n'):
                    _ingest(frag, date.today().isoformat())
                    frag = ''
            else:
                time.sleep(0.4)
        except FileNotFoundError:
            time.sleep(2)
        except OSError:
            f, ino, frag = None, None, ''
            time.sleep(2)

# ── event bus (SSE fan-out) ──────────────────────────────────────────────
SUBS = set()
SUBS_LOCK = threading.Lock()

def publish(ev):
    data = json.dumps(ev, ensure_ascii=False)
    with SUBS_LOCK:
        for q in list(SUBS):
            try:
                q.put_nowait(data)
            except queue.Full:
                SUBS.discard(q)

def set_status(up):
    global SERVER_UP
    if SERVER_UP != up:
        SERVER_UP = up
        publish({'type': 'status', 'up': up})

# ── metrics sampler ──────────────────────────────────────────────────────
def is_our_java(pid):
    """True if pid is still a java process cwd'd in SERVER_DIR — guards against
    pid reuse handing us an unrelated process's RSS/CPU."""
    try:
        return os.readlink(f'/proc/{pid}/cwd') == str(SERVER_DIR) and \
            b'java' in open(f'/proc/{pid}/cmdline', 'rb').read()
    except OSError:
        return False

def find_java_pid():
    if not os.path.isdir('/proc'):   # ponytail: Windows/mac — no /proc, RAM/CPU tiles stay empty
        return None
    for p in os.listdir('/proc'):
        if p.isdigit() and is_our_java(int(p)):
            return int(p)
    return None

def metrics_loop():
    global ONLINE
    pid, prev_cpu, prev_t = None, None, None
    clk = os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100
    while True:
        out = rcon('list', timeout=5)
        set_status(out is not None)
        players = names_after_colon(out) if out else []
        with BUF_LOCK:
            ONLINE = players
        tps = None
        if out is not None:
            t_out = rcon('tps', timeout=5) or ''
            if m := re.search(r':\s*\*?([\d.]+)', t_out):
                tps = min(float(m[1]), 20.0)
        rss = cpu = None
        if pid is None or not is_our_java(pid):   # revalidate every sample
            pid, prev_cpu = find_java_pid(), None
        if pid:
            try:
                stat = open(f'/proc/{pid}/stat').read().rsplit(')', 1)[1].split()
                total = (int(stat[11]) + int(stat[12])) / clk   # utime+stime
                now = time.time()
                if prev_cpu is not None and now > prev_t:
                    cpu = round((total - prev_cpu) / (now - prev_t) * 100, 1)
                prev_cpu, prev_t = total, now
                rss = int(open(f'/proc/{pid}/statm').read().split()[1]) \
                    * os.sysconf('SC_PAGE_SIZE') // 1048576
            except (OSError, IndexError, ValueError):
                pid = None
        with BUF_LOCK:
            METRICS.append((int(time.time()), len(players), tps, rss, cpu))
        publish({'type': 'metric', 'ts': int(time.time()),
                 'players': len(players), 'tps': tps, 'mem': rss, 'cpu': cpu})
        time.sleep(20)

# ── backups ──────────────────────────────────────────────────────────────
BACKUP_LOCK = threading.Lock()
EDIT_LOCK = threading.Lock()   # serialize file_put: shared .remora-tmp name
                               # made concurrent saves of one file crash on replace
BACKUP_NAME = re.compile(r'^backup-\d{8}-\d{6}\.tgz$')

def backup_targets():
    level = 'world'
    try:
        for ln in open(SERVER_DIR / 'server.properties',
                       encoding='utf-8', errors='replace'):
            if ln.startswith('level-name='):
                level = ln.split('=', 1)[1].strip() or 'world'
    except OSError:
        pass
    tgt = [p for p in SERVER_DIR.iterdir() if p.is_dir() and
           (p.name == level or p.name.startswith(level + '_'))]  # world, world_nether…
    tgt += [p for p in SERVER_DIR.iterdir() if p.is_file() and
            p.suffix in ('.properties', '.yml', '.yaml', '.json', '.txt')
            and p.name != 'remora.json']
    if (SERVER_DIR / 'plugins').is_dir():
        tgt.append(SERVER_DIR / 'plugins')
    return tgt

def run_backup(reason='manual'):
    if not BACKUP_LOCK.acquire(blocking=False):
        publish({'type': 'backup', 'ok': False, 'msg': 'backup already running'})
        return 'backup already running'
    try:
        # Server up but RCON unresponsive → don't tar a live-written world.
        # Liveness probe must be 'list', NOT 'save-off': the disk-space guard
        # below can return early, and save-off is only undone by the finally
        # after line ~389 — probing with save-off left autosave off forever.
        if SERVER_UP and rcon('list') is None:
            publish({'type': 'backup', 'ok': False,
                     'msg': 'server not responding — backup aborted'})
            return 'server unresponsive'
        targets = backup_targets()
        need = sum(f.stat().st_size for t in targets for f in
                   (t.rglob('*') if t.is_dir() else [t]) if f.is_file())
        if shutil.disk_usage(SERVER_DIR).free < need * 0.8 + 500_000_000:
            publish({'type': 'backup', 'ok': False, 'msg': 'not enough disk space'})
            return 'not enough disk space'
        publish({'type': 'backup', 'ok': True, 'msg': f'backup started ({reason})'})
        BACKUP_DIR.mkdir(exist_ok=True)
        name = f'backup-{datetime.now():%Y%m%d-%H%M%S}.tgz'
        rcon('save-off')
        rcon('save-all flush')
        time.sleep(3)
        try:
            def flt(ti):
                return None if '/backups/' in ti.name or ti.name.endswith('.jar') \
                    else ti
            try:
                # dereference=True: a symlinked world dir would otherwise store
                # only the bare symlink entry — a '0 MB done' backup with no data.
                with tarfile.open(BACKUP_DIR / name, 'w:gz', compresslevel=1,
                                  dereference=True) as tar:
                    for t in targets:
                        tar.add(t, arcname=t.name, filter=flt)
            except OSError:
                # a file vanishing mid-tar leaves a well-formed but INCOMPLETE
                # archive that reads clean and would displace a good one at prune.
                (BACKUP_DIR / name).unlink(missing_ok=True)
                raise
        finally:
            rcon('save-on')
        keep = max(1, int(STATE.get('keep_backups', 5)))   # never prune to zero
        for p in sorted(BACKUP_DIR.glob('backup-*.tgz'))[:-keep]:
            p.unlink()
        size = (BACKUP_DIR / name).stat().st_size
        publish({'type': 'backup', 'ok': True, 'done': True,
                 'msg': f'{name} done ({size // 1048576} MB)'})
        return None
    except OSError as e:
        publish({'type': 'backup', 'ok': False, 'msg': f'backup failed: {e}'})
        return str(e)
    finally:
        BACKUP_LOCK.release()

def list_backups():
    if not BACKUP_DIR.is_dir():
        return []
    out = []
    for p in sorted(BACKUP_DIR.glob('backup-*.tgz'), reverse=True):
        try:
            st = p.stat()
        except OSError:                  # pruned concurrently — skip
            continue
        out.append({'name': p.name, 'size': st.st_size, 'ts': int(st.st_mtime)})
    return out

# ── power control ────────────────────────────────────────────────────────
def power(op):
    """start/stop/restart in a background thread; attach-mode: start uses the
    admin-configured command (e.g. 'systemctl start minecraft'), stop is a
    graceful rcon stop. Returns an error string, or None if the op began."""
    start_cmd = STATE.get('start_cmd', '')
    if op in ('start', 'restart') and not start_cmd:
        # refuse BEFORE stopping anything: a restart with no start command
        # used to stop the server and only then discover it couldn't start it
        # back — a scheduled 3am restart left the server down until morning.
        msg = 'no start command configured (Settings)'
        publish({'type': 'backup', 'ok': False, 'msg': msg})   # scheduler path
        return msg
    def go():
        if op in ('stop', 'restart'):
            rcon('stop')
            for _ in range(60):
                if rcon('list', timeout=3) is None:
                    break
                time.sleep(2)
            set_status(False)
        if op in ('start', 'restart'):
            time.sleep(2)
            try:
                subprocess.run(start_cmd, shell=True, timeout=120,
                               capture_output=True)
            except subprocess.SubprocessError as e:
                publish({'type': 'backup', 'ok': False, 'msg': f'start failed: {e}'})
    threading.Thread(target=go, daemon=True).start()
    return None

# ── scheduler ────────────────────────────────────────────────────────────
def scheduler_loop():
    # ponytail: last-fired kept in memory — a panel restart in the exact
    # scheduled minute could double-fire; harmless for backup/restart.
    fired = {}
    while True:
        now = datetime.now()
        stamp = now.strftime('%H:%M')
        today = now.date().isoformat()
        for sc in list(STATE.get('schedules', [])):
            key = (sc.get('time'), sc.get('action'))   # index-independent: edits
            if sc.get('time') == stamp and fired.get(key) != today:  # don't refire
                fired[key] = today
                act = sc.get('action', '')
                if act == 'backup':
                    threading.Thread(target=run_backup, args=('scheduled',),
                                     daemon=True).start()
                elif act == 'restart':
                    power('restart')
                elif act:
                    rcon(act)
        time.sleep(20)

# ── file manager helpers ─────────────────────────────────────────────────
def safe_path(base, rel):
    """Resolve rel inside base; None if it escapes (.. or symlink) or carries
    control chars (CR/LF would let a crafted filename inject response headers
    via Content-Disposition in stream_file)."""
    if rel.startswith(('/', '\\')) or any(ord(c) < 32 for c in rel):
        return None
    p = (base / rel).resolve()
    base = base.resolve()
    if p != base and base not in p.parents:
        return None
    if p.name.lower() == 'remora.json':   # case-insensitive: NTFS/APFS treat
        return None                        # REMORA.JSON as the same file → leak
    return p

# ── HTTP ─────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = f'remora/{VERSION}'
    timeout = 60   # reap idle keep-alive conns and slowloris half-requests

    # -- plumbing --
    def _ip(self):
        """Rate-limit key. A client can forge X-Forwarded-For, so only trust it
        when the actual peer is loopback (i.e. our own reverse proxy), and then
        use the LAST entry — the one the trusted proxy appended, not the
        leftmost value the client controls."""
        peer = self.client_address[0]
        if peer in ('127.0.0.1', '::1'):
            fwd = [x.strip() for x in
                   self.headers.get('X-Forwarded-For', '').split(',') if x.strip()]
            if fwd:
                return fwd[-1]
        return peer

    def _send(self, code, body, ctype='text/html; charset=utf-8', extra=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   'application/json; charset=utf-8')

    def _authed(self):
        if NO_AUTH:
            return True
        c = SimpleCookie(self.headers.get('Cookie', ''))
        return 'r_s' in c and check_token(STATE['secret'], c['r_s'].value)

    def _body(self):
        try:
            ln = int(self.headers.get('Content-Length', 0))
        except ValueError:
            return None
        if ln > 2_000_000:
            return None
        return self.rfile.read(ln)

    def _origin_ok(self):
        origin = self.headers.get('Origin')
        if not origin:
            return True
        host = urllib.parse.urlsplit(origin).netloc
        return host == self.headers.get('Host', '')

    def log_message(self, *a):
        pass

    # -- GET --
    def do_GET(self):
        path, _, qs = self.path.partition('?')
        q = urllib.parse.parse_qs(qs)
        if path == '/login':
            return self._send(200, LOGIN_PAGE)
        if not self._authed():
            if path == '/':
                return self._send(200, LOGIN_PAGE)
            return self._json({'error': 'auth'}, 401)
        if path == '/':
            return self._send(200, PAGE)
        if path == '/state.json':
            return self._json(self.state())
        if path == '/events':
            return self.sse()
        if path == '/files':
            return self.files(q.get('d', [''])[0])
        if path == '/file':
            return self.file_get(q.get('p', [''])[0], 'raw' in q)
        if path == '/backup/dl':
            return self.backup_dl(q.get('f', [''])[0])
        self._json({'error': 'not found'}, 404)

    # -- POST --
    def do_POST(self):
        # Drain the body BEFORE any early rejection — an unread body corrupts
        # the keep-alive stream (leftover bytes get parsed as the next request).
        raw = self._body()
        if raw is None:
            self.close_connection = True   # oversized body was never drained
            return self._json({'error': 'body too large'}, 413)
        if not self._origin_ok():
            return self._json({'error': 'bad origin'}, 403)
        path = self.path.partition('?')[0]
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):   # "[]"/"null" must not crash the handler
            body = {}
        if path == '/login':
            return self.login(body)
        if not self._authed():
            return self._json({'error': 'auth'}, 401)
        if path == '/logout':
            return self._json({'ok': True}, 200) if NO_AUTH else self._send(
                200, '{"ok": true}', 'application/json',
                [('Set-Cookie', 'r_s=; Max-Age=0; Path=/')])
        if path == '/cmd':
            return self.cmd(body)
        if path == '/action':
            return self.action(body)
        if path == '/file':
            return self.file_put(body)
        if path == '/backup':
            threading.Thread(target=run_backup, daemon=True).start()
            return self._json({'ok': True})
        if path == '/backup/del':
            return self.backup_del(body)
        if path == '/power':
            if body.get('op') in ('start', 'stop', 'restart'):
                err = power(body['op'])
                return self._json({'error': err}, 400) if err \
                    else self._json({'ok': True})
            return self._json({'error': 'bad op'}, 400)
        if path == '/settings':
            return self.settings(body)
        if path == '/password':
            return self.password(body)
        self._json({'error': 'not found'}, 404)

    # -- handlers --
    def login(self, body):
        ip = self._ip()
        if not login_allowed(ip):
            return self._json({'error': 'too many attempts, wait 5 min'}, 429)
        if check_pw(str(body.get('password', ''))):
            tok = make_token(STATE['secret'])
            cookie = f'r_s={tok}; Path=/; Max-Age={7*86400}; HttpOnly; SameSite=Lax'
            # Secure only when the request really came over TLS (reverse proxy
            # sets X-Forwarded-Proto). Marking it Secure on plain HTTP makes
            # browsers DROP the cookie on non-localhost origins — which locked
            # out LAN users (http://192.168.x.x) in an endless login loop.
            if self.headers.get('X-Forwarded-Proto', '') == 'https':
                cookie += '; Secure'
            return self._send(200, '{"ok": true}', 'application/json',
                              [('Set-Cookie', cookie)])
        login_failed(ip)
        return self._json({'error': 'wrong password'}, 403)

    def state(self):
        # skip RCON entirely when the server is known down, and cap the two
        # round-trips short so a hung server can't stall the whole panel.
        if SERVER_UP is False:
            wl, banned = [], []
        else:
            wl = names_after_colon(rcon('whitelist list', timeout=4) or '')
            ban_out = rcon('banlist players', timeout=4) or ''
            banned = re.findall(r'([^\s,:]{1,48}) was banned', ban_out)
        with BUF_LOCK:
            feed = list(FEED)
            console = list(CONSOLE)
            metrics = list(METRICS)
            attempts = [{'name': n, 't': t} for n, t in ATTEMPTS.items()
                        if n not in wl]
            online = list(ONLINE)
        return {
            'version': VERSION, 'up': SERVER_UP, 'online': online,
            'whitelist': wl, 'banned': banned, 'attempts': attempts,
            'feed': feed[-400:], 'console': console,
            'metrics': [{'ts': m[0], 'players': m[1], 'tps': m[2],
                         'mem': m[3], 'cpu': m[4]} for m in metrics],
            'backups': list_backups(),
            'schedules': STATE.get('schedules', []),
            'keep_backups': STATE.get('keep_backups', 5),
            'start_cmd': STATE.get('start_cmd', ''),
            'no_auth': NO_AUTH,
        }

    def sse(self):
        with SUBS_LOCK:
            if len(SUBS) >= 32:
                return self._json({'error': 'too many listeners'}, 503)
            q = queue.Queue(maxsize=500)
            SUBS.add(q)
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(b': hi\n\n')
            self.wfile.flush()
            while True:
                with SUBS_LOCK:
                    if q not in SUBS:    # dropped as a slow consumer — close so
                        break            # the browser's EventSource reconnects
                try:
                    data = q.get(timeout=15)
                    self.wfile.write(f'data: {data}\n\n'.encode())
                except queue.Empty:
                    self.wfile.write(b': ping\n\n')
                self.wfile.flush()
        except OSError:
            pass
        finally:
            # SSE has no Content-Length, so this conn can't carry another
            # response; without close an evicted slow consumer zombies in
            # keep-alive for 60s and its EventSource never reconnects.
            self.close_connection = True
            with SUBS_LOCK:
                SUBS.discard(q)

    def cmd(self, body):
        c = str(body.get('c', '')).strip()[:256]
        if not c:
            return self._json({'error': 'empty'}, 400)
        out = rcon(c)
        return self._json({'out': out, 'up': out is not None})

    ACTIONS = {'whitelist_add': 'whitelist add', 'whitelist_remove':
               'whitelist remove', 'kick': 'kick', 'ban': 'ban',
               'pardon': 'pardon', 'op': 'op', 'deop': 'deop'}

    def action(self, body):
        name = str(body.get('name', ''))
        act = body.get('action', '')
        if act not in self.ACTIONS or not re.fullmatch(r'[A-Za-z0-9_. ]{1,48}',
                                                       name):
            return self._json({'error': 'bad request'}, 400)
        cmd = self.ACTIONS[act]
        # Bedrock names (Floodgate '.' prefix) go through fwhitelist
        if name.startswith('.') and cmd.startswith('whitelist'):
            cmd, name = cmd.replace('whitelist', 'fwhitelist'), name[1:]
        out = rcon(f'{cmd} {name}')
        return self._json({'out': out, 'up': out is not None})

    def files(self, rel):
        p = safe_path(SERVER_DIR, rel)
        if not p or not p.is_dir():
            return self._json({'error': 'bad path'}, 400)
        items = []
        for c in sorted(p.iterdir(), key=lambda c: (c.is_file(), c.name.lower())):
            if c.name == 'remora.json':
                continue
            try:
                items.append({'name': c.name, 'dir': c.is_dir(),
                              'size': c.stat().st_size if c.is_file() else 0})
            except OSError:
                pass
        return self._json({'path': rel, 'items': items})

    def file_get(self, rel, raw):
        p = safe_path(SERVER_DIR, rel)
        if not p or not p.is_file():
            return self._json({'error': 'bad path'}, 400)
        if raw:
            return self.stream_file(p, 'application/octet-stream')
        if p.stat().st_size > 512_000:
            return self._json({'error': 'too large to edit — use download'}, 400)
        data = p.read_bytes()
        if b'\x00' in data[:8192]:
            return self._json({'error': 'binary file — use download'}, 400)
        return self._json({'content': data.decode(errors='replace')})

    def file_put(self, body):
        p = safe_path(SERVER_DIR, str(body.get('p', '')))
        if not p or not p.parent.is_dir() or (p.exists() and not p.is_file()):
            return self._json({'error': 'bad path'}, 400)
        content = str(body.get('content', ''))
        with EDIT_LOCK:   # shared tmp name → concurrent saves raced on replace()
            if p.is_file():
                shutil.copy2(p, str(p) + '.bak')
            tmp = p.with_name(p.name + '.remora-tmp')
            # utf-8 + LF: Windows ANSI codepage would mojibake/crash on non-ASCII
            # config values and translate LF→CRLF on save.
            tmp.write_text(content, encoding='utf-8', newline='\n')
            tmp.replace(p)
        return self._json({'ok': True})

    def stream_file(self, p, ctype):
        st = p.stat()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(st.st_size))
        self.send_header('Content-Disposition',
                         f'attachment; filename="{p.name}"')
        self.end_headers()
        try:
            with open(p, 'rb') as f:     # bound to the stat'd size so a file
                remaining = st.st_size    # appended-to mid-stream can't desync
                while remaining > 0:      # Content-Length (corrupts keep-alive)
                    buf = f.read(min(65536, remaining))
                    if not buf:
                        self.close_connection = True   # short read: file shrank,
                        break                          # fewer bytes than promised
                    self.wfile.write(buf)
                    remaining -= len(buf)
        except OSError:
            self.close_connection = True   # partial body already on the wire

    def backup_dl(self, name):
        if not BACKUP_NAME.fullmatch(name):
            return self._json({'error': 'bad name'}, 400)
        p = BACKUP_DIR / name
        if not p.is_file():
            return self._json({'error': 'not found'}, 404)
        return self.stream_file(p, 'application/gzip')

    def backup_del(self, body):
        name = str(body.get('f', ''))
        if not BACKUP_NAME.fullmatch(name):
            return self._json({'error': 'bad name'}, 400)
        try:
            (BACKUP_DIR / name).unlink()
        except OSError:
            return self._json({'error': 'not found'}, 404)
        return self._json({'ok': True})

    def settings(self, body):
        with STATE_LOCK:
            if 'keep_backups' in body:
                try:
                    STATE['keep_backups'] = max(1, min(50, int(body['keep_backups'])))
                except (TypeError, ValueError):
                    pass
            if 'start_cmd' in body:
                STATE['start_cmd'] = str(body['start_cmd'])[:300]
            if 'schedules' in body and isinstance(body['schedules'], list):
                clean = []
                for sc in body['schedules'][:20]:
                    t = str(sc.get('time', ''))
                    a = str(sc.get('action', ''))[:200]
                    if re.fullmatch(r'\d\d:\d\d', t) and a:
                        clean.append({'time': t, 'action': a})
                STATE['schedules'] = clean
            save_state()
        return self._json({'ok': True})

    def password(self, body):
        if not check_pw(str(body.get('old', ''))):
            return self._json({'error': 'wrong password'}, 403)
        new = str(body.get('new', ''))
        if len(new) < 8:
            return self._json({'error': 'min 8 characters'}, 400)
        with STATE_LOCK:
            STATE['pw'] = hash_pw(new)
            STATE['secret'] = secrets.token_hex(32)  # invalidate old sessions
            save_state()
        return self._json({'ok': True})

# ── UI (single embedded page; all URLs relative → works behind any prefix) ─
LOGIN_PAGE = '''<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>remora — login</title>
<link rel=icon href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='13' font-size='13'>&#129416;</text></svg>">
<style>body{font:15px system-ui;background:#0d0d0d;color:#eee;display:grid;place-items:center;height:100vh;margin:0}
form{background:#111;border:1px solid #2c2c2a;border-radius:12px;padding:2em;display:grid;gap:10px;width:260px}
input{background:#1a1a19;color:#eee;border:1px solid #383835;border-radius:8px;padding:8px}
button{background:#3987e5;color:#fff;border:0;border-radius:8px;padding:8px;cursor:pointer;font-weight:600}
.err{color:#e66767;font-size:.9em;min-height:1.2em;margin:0}</style>
<form id=f><b>&#129416; remora</b><input type=password id=pw placeholder=password autofocus>
<button>sign in</button><p class=err id=err></p></form>
<script>
f.onsubmit=async e=>{e.preventDefault();
 const r=await fetch('login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({password:pw.value})});
 if(r.ok)location='./';else err.textContent=(await r.json()).error||'error';};
</script>'''

PAGE = r'''<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>remora</title>
<link rel=icon href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='13' font-size='13'>&#129416;</text></svg>">
<style>
:root{--bg:#0d0d0d;--card:#111;--line:#2c2c2a;--ink:#fff;--ink2:#c3c2b7;--mut:#898781;
--blue:#3987e5;--aqua:#199e70;--yellow:#c98500;--red:#e66767;--good:#0ca30c;--warn:#fab219}
*{box-sizing:border-box}body{font:15px system-ui;background:var(--bg);color:var(--ink2);margin:0}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:2}
nav{overflow-x:auto}
header b{color:var(--ink)}#dot{width:9px;height:9px;border-radius:50%;background:#555}
#dot.up{background:var(--good)}#dot.down{background:var(--red)}
nav{display:flex;gap:4px;margin-left:auto}
nav button,#logout{background:none;border:0;color:var(--mut);padding:6px 10px;border-radius:8px;cursor:pointer;font:inherit}
nav button.on{background:var(--card);color:var(--ink)}nav button:hover,#logout:hover{color:var(--ink)}
main{max-width:1080px;margin:14px auto;padding:0 14px}section{display:none}section.on{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.card h3{margin:0 0 6px;font-size:.8em;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.big{font-size:1.7em;color:var(--ink);font-weight:650}.sub{font-size:.8em;color:var(--mut);min-height:1.2em}
svg.spark{width:100%;height:44px;display:block;margin-top:4px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
@media(max-width:760px){.grid2{grid-template-columns:1fr}}
.row{display:flex;gap:8px;align-items:center;padding:4px 0}.row b{flex:1;color:var(--ink);font-weight:500;overflow:hidden;text-overflow:ellipsis}
.row .t{color:var(--mut);font-size:.8em}
button.act{background:#1a1a19;color:var(--ink2);border:1px solid #383835;border-radius:7px;padding:3px 9px;cursor:pointer;font-size:.85em}
button.act:hover{background:#222;color:var(--ink)}button.prime{background:var(--blue);border-color:var(--blue);color:#fff}
input,select,textarea{background:#1a1a19;color:#eee;border:1px solid #383835;border-radius:8px;padding:6px 9px;font:inherit}
.feed{height:340px;overflow-y:auto;font-size:.92em}
.feed p{margin:2px 0}.feed .t{color:var(--mut);font-size:.85em;margin-right:6px}
.feed .n{color:var(--ink);font-weight:600}.feed .sys{color:var(--mut);font-style:italic}
.feed .say .n{color:var(--blue)}
#console{height:420px;overflow-y:auto;background:#0a0a0a;border:1px solid var(--line);border-radius:10px;padding:10px;
font:12.5px ui-monospace,monospace;white-space:pre-wrap;word-break:break-all;color:#b8b8b0}
#console .me{color:var(--blue)}.bar{display:flex;gap:8px;margin-top:8px}.bar input{flex:1}
table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;text-align:left;border-bottom:1px solid var(--line);font-size:.92em}
th{color:var(--mut);font-weight:600}td:last-child{text-align:right;white-space:nowrap}
#crumb button{background:none;border:0;color:var(--blue);cursor:pointer;font:inherit;padding:0}
.fitem{display:flex;gap:8px;padding:5px 8px;border-radius:7px;cursor:pointer}
.fitem:hover{background:#1a1a19}.fitem .sz{margin-left:auto;color:var(--mut);font-size:.85em}
#editor{width:100%;height:400px;font:12.5px ui-monospace,monospace;white-space:pre;tab-size:2}
#toasts{position:fixed;bottom:14px;right:14px;display:grid;gap:8px;z-index:9}
.toast{background:#1a1a19;border:1px solid #383835;border-left:3px solid var(--good);border-radius:9px;padding:9px 13px;max-width:340px;font-size:.9em}
.toast.bad{border-left-color:var(--red)}
.chip{display:inline-flex;gap:6px;align-items:center;background:#1a1a19;border:1px solid #383835;border-radius:999px;padding:2px 10px;margin:2px;font-size:.9em;color:var(--ink)}
.chip button{background:none;border:0;color:var(--mut);cursor:pointer;padding:0}
.warntxt{color:var(--warn)}h2{font-size:.95em;color:var(--ink);margin:16px 0 8px}
label{font-size:.85em;color:var(--mut);display:block;margin:10px 0 4px}
</style>
<header><span>&#129416;</span><b>remora</b><span id=dot title=offline></span>
<span id=upinfo class=sub></span>
<nav>
<button data-s=dash class=on>Dashboard</button><button data-s=cons>Console</button>
<button data-s=files>Files</button><button data-s=back>Backups</button>
<button data-s=set>Settings</button></nav>
<button id=logout title=logout>&#10162;</button></header>
<main>
<section id=dash class=on>
 <div class=cards>
  <div class=card><h3>Players online</h3><div class=big id=vPlayers>–</div>
   <div class=sub id=sPlayers></div><svg class=spark id=gPlayers></svg></div>
  <div class=card><h3>TPS</h3><div class=big id=vTps>–</div>
   <div class=sub id=sTps></div><svg class=spark id=gTps></svg></div>
  <div class=card><h3>Memory (java)</h3><div class=big id=vMem>–</div>
   <div class=sub id=sMem></div><svg class=spark id=gMem></svg></div>
 </div>
 <div class=grid2>
  <div class=card><h3>&#128172; Chat</h3><div class=feed id=chat></div>
   <div class=bar><input id=sayIn maxlength=256 placeholder="say as server…">
   <button class="act prime" id=sayBtn>send</button></div></div>
  <div>
   <div class=card><h3>&#128994; Online</h3><div id=online></div></div>
   <div class=card style="margin-top:12px"><h3>&#9203; Rejected joins (not whitelisted)</h3><div id=attempts></div></div>
   <div class=card style="margin-top:12px"><h3>&#128203; Whitelist</h3><div id=wl></div>
    <div class=bar><input id=wlIn maxlength=48 placeholder="add player…">
    <button class=act id=wlBtn>add</button></div></div>
   <div class=card style="margin-top:12px"><h3>&#128683; Banned</h3><div id=banned></div></div>
  </div>
 </div>
</section>
<section id=cons>
 <div id=console></div>
 <div class=bar><input id=cmdIn placeholder="rcon command… (e.g. list, tps, say hi)" maxlength=256>
 <button class="act prime" id=cmdBtn>run</button>
 <button class=act id=pwrStart>&#9654; start</button>
 <button class=act id=pwrRestart>&#8635; restart</button>
 <button class=act id=pwrStop>&#9632; stop</button></div>
</section>
<section id=files>
 <div class=card><div id=crumb></div><div id=flist></div></div>
 <div class=card id=fedit style="display:none;margin-top:12px">
  <div class=bar style="margin:0 0 8px"><b id=fname style="flex:1;color:var(--ink)"></b>
  <a id=fdl class=act style="text-decoration:none;padding:4px 9px">download</a>
  <button class="act prime" id=fsave>save</button></div>
  <textarea id=editor spellcheck=false></textarea></div>
</section>
<section id=back>
 <div class=card>
 <div class=bar style="margin:0 0 10px"><h3 style="flex:1;margin:0">World backups</h3>
 <button class="act prime" id=bkNow>backup now</button></div>
 <table><thead><tr><th>file</th><th>size</th><th>date</th><th></th></tr></thead>
 <tbody id=bkList></tbody></table>
 <p class=sub>Restore: stop the server, then <code>tar xzf backups/&lt;file&gt; -C /path/to/server</code></p></div>
</section>
<section id=set>
 <div class=card><h3>Settings</h3>
  <label>Start command (used by start/restart; e.g. <code>systemctl start minecraft</code>)</label>
  <input id=setStart style="width:100%">
  <label>Backups to keep</label><input id=setKeep type=number min=1 max=50 style="width:90px">
  <h2>Schedules (server local time)</h2><div id=schedList></div>
  <div class=bar><input id=schedT type=time><select id=schedA>
   <option value=backup>backup</option><option value=restart>restart</option>
   <option value=custom>custom command…</option></select>
   <input id=schedC placeholder="say Server restart in 5 min" style="flex:1;display:none">
   <button class=act id=schedAdd>add</button></div>
  <div class=bar><button class="act prime" id=setSave>save settings</button></div>
  <h2>Change password</h2>
  <div class=bar><input id=pwOld type=password placeholder=current>
  <input id=pwNew type=password placeholder="new (min 8)">
  <button class=act id=pwBtn>change</button></div></div>
</section>
</main><div id=toasts></div>
<script>
'use strict';
const $=s=>document.querySelector(s);
let S=null, sched=[];
const api=async(p,body)=>{let r;
 try{r=await fetch(p,body?{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});}
 catch(e){toast('network error',1);throw e}
 if(r.status===401){location='login';throw 0}
 if(!r.ok){let m='HTTP '+r.status;try{m=(await r.json()).error||m}catch(e){}
  toast(m,1);throw new Error(m)}
 try{return await r.json()}catch(e){toast('bad response',1);throw e}};
const toast=(msg,bad)=>{const d=document.createElement('div');
 d.className='toast'+(bad?' bad':'');d.textContent=msg;$('#toasts').append(d);
 setTimeout(()=>d.remove(),5000)};

// tabs
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
 document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));
 document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id===b.dataset.s));
 // console was seeded while hidden (scrollHeight 0) → land at newest, not oldest;
 // !scrollTop guard preserves a deliberate scroll-up.
 if(b.dataset.s==='cons'){const c=$('#console');if(!c.scrollTop)c.scrollTop=c.scrollHeight}});
$('#logout').onclick=async()=>{await api('logout',{});location='login'};

// ── dashboard ──
const fmtT=ts=>new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
function feedLine(e){const p=document.createElement('p');
 const t=document.createElement('span');t.className='t';t.textContent=(e.d?e.d.slice(5)+' ':'')+e.t;p.append(t);
 if(e.type==='chat'){if(e.say)p.className='say';
  const n=document.createElement('span');n.className='n';n.textContent=e.name+': ';p.append(n);
  p.append(document.createTextNode(e.msg));}
 else{const s=document.createElement('span');s.className='sys';
  s.textContent=e.name+(e.type==='join'?' joined':' left');p.append(s);}
 return p}
function renderFeed(){const c=$('#chat');
 const stick=c.scrollTop+c.clientHeight>=c.scrollHeight-30||!c.childElementCount;
 c.textContent='';S.feed.forEach(e=>c.append(feedLine(e)));
 if(stick)c.scrollTop=c.scrollHeight}
function rows(el,names,acts){el.textContent='';
 if(!names.length){el.innerHTML='<p class=sub>none</p>';return}
 names.forEach(item=>{const name=item.name??item, t=item.t;
  const r=document.createElement('div');r.className='row';
  if(t){const ts=document.createElement('span');ts.className='t';ts.textContent=t;r.append(ts)}
  const b=document.createElement('b');b.textContent=name;r.append(b);
  acts.forEach(([lbl,act])=>{const btn=document.createElement('button');
   btn.className='act';btn.textContent=lbl;
   btn.onclick=async()=>{const o=await api('action',{action:act,name});
    toast(o.out||lbl+' → '+name);refresh()};r.append(btn)});
  el.append(r)})}
function renderLists(){
 rows($('#online'),S.online,[['kick','kick'],['ban','ban']]);
 rows($('#attempts'),S.attempts,[['✅ whitelist','whitelist_add'],['🔨 ban','ban']]);
 rows($('#wl'),S.whitelist,[['remove','whitelist_remove']]);
 rows($('#banned'),S.banned,[['🕊 pardon','pardon']]);}
$('#wlBtn').onclick=async()=>{const n=$('#wlIn').value.trim();if(!n)return;
 const o=await api('action',{action:'whitelist_add',name:n});
 toast(o.out||'added');$('#wlIn').value='';refresh()};
$('#wlIn').onkeydown=e=>{if(e.key==='Enter')$('#wlBtn').onclick()};
$('#sayBtn').onclick=send_say;$('#sayIn').onkeydown=e=>{if(e.key==='Enter')send_say()};
async function send_say(){const m=$('#sayIn').value.trim();if(!m)return;
 await api('cmd',{c:'say '+m});$('#sayIn').value=''}

// ── sparklines (single-series stat tiles; colors validated for dark surface) ──
const SPARKS={gPlayers:{k:'players',c:'#3987e5',v:'vPlayers',s:'sPlayers',min:0,fmt:v=>v},
 gTps:{k:'tps',c:'#199e70',v:'vTps',s:'sTps',min:0,max:20,fmt:v=>v==null?'–':v.toFixed(1)},
 gMem:{k:'mem',c:'#c98500',v:'vMem',s:'sMem',min:0,fmt:v=>v==null?'–':v+' MB'}};
let M=[];
function drawSparks(){for(const[id,cfg]of Object.entries(SPARKS))drawSpark(id,cfg)}
function drawSpark(id,cfg){
 const svg=$('#'+id),W=svg.clientWidth||260,H=44,PAD=3;
 const pts=M.slice(-180).map(m=>({ts:m.ts,v:m[cfg.k]})).filter(p=>p.v!=null);
 const last=pts.length?pts[pts.length-1]:null;
 $('#'+cfg.v).textContent=last?cfg.fmt(last.v):'–';
 if(cfg.k==='tps'&&last)$('#'+cfg.v).className='big'+(last.v<15?' warntxt':'');
 if(pts.length<2){svg.textContent='';svg.onmousemove=svg.onmouseleave=null;
  $('#'+cfg.s).textContent='';return}
 const min=cfg.min??Math.min(...pts.map(p=>p.v)),
       max=cfg.max??Math.max(...pts.map(p=>p.v),min+1);
 const x=i=>PAD+i/(pts.length-1)*(W-2*PAD),
       y=v=>H-PAD-(v-min)/(max-min)*(H-2*PAD);
 const line=pts.map((p,i)=>`${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ');
 svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
 svg.innerHTML=`<line x1=0 y1=${H-1} x2=${W} y2=${H-1} stroke=#383835 stroke-width=1/>
  <polygon points="${PAD},${H-PAD} ${line} ${x(pts.length-1)},${H-PAD}" fill="${cfg.c}" opacity=.14/>
  <polyline points="${line}" fill=none stroke="${cfg.c}" stroke-width=2 stroke-linejoin=round/>`;
 svg.onmousemove=e=>{const r=svg.getBoundingClientRect();
  const i=Math.max(0,Math.min(pts.length-1,Math.round((e.clientX-r.left)/r.width*(pts.length-1))));
  $('#'+cfg.s).textContent=fmtT(pts[i].ts)+' · '+cfg.fmt(pts[i].v)};
 svg.onmouseleave=()=>{$('#'+cfg.s).textContent=''};}

// ── console ──
function consLine(txt,me){const c=$('#console'),stick=c.scrollTop+c.clientHeight>=c.scrollHeight-30;
 const d=document.createElement('div');if(me)d.className='me';d.textContent=txt;c.append(d);
 while(c.childElementCount>600)c.firstChild.remove();
 if(stick)c.scrollTop=c.scrollHeight}
let hist=[],hi=0;
$('#cmdBtn').onclick=runCmd;
$('#cmdIn').onkeydown=e=>{if(e.key==='Enter')runCmd();
 else if(e.key==='ArrowUp'&&hi>0){hi--;$('#cmdIn').value=hist[hi];e.preventDefault()}
 else if(e.key==='ArrowDown'&&hi<hist.length){hi++;$('#cmdIn').value=hist[hi]||'';e.preventDefault()}};
async function runCmd(){const c=$('#cmdIn').value.trim();if(!c)return;
 hist.push(c);hi=hist.length;consLine('> '+c,true);$('#cmdIn').value='';
 const o=await api('cmd',{c});
 consLine(o.up?(o.out||'(no output)'):'(server offline)')}
for(const[id,op]of[['pwrStart','start'],['pwrRestart','restart'],['pwrStop','stop']])
 $('#'+id).onclick=async()=>{if(op!=='start'&&!confirm(op+' the server?'))return;
  await api('power',{op});toast('power: '+op)};

// ── files ──
let cwd='',openFile=null;
async function loadDir(d){const o=await api('files?d='+encodeURIComponent(d));
 if(o.error)return toast(o.error,1);cwd=d;
 const cr=$('#crumb');cr.textContent='';
 let acc='';const parts=['server',...d.split('/').filter(Boolean)];
 parts.forEach((seg,i)=>{const p=i===0?'':(acc+=(acc?'/':'')+seg,acc);
  const b=document.createElement('button');b.textContent=seg;
  b.onclick=()=>loadDir(i===0?'':p);cr.append(b);
  if(i<parts.length-1)cr.append(document.createTextNode(' / '))});
 const fl=$('#flist');fl.textContent='';
 o.items.forEach(it=>{const r=document.createElement('div');r.className='fitem';
  r.innerHTML=`<span>${it.dir?'📁':'📄'}</span>`;
  const n=document.createElement('span');n.textContent=it.name;r.append(n);
  if(!it.dir){const s=document.createElement('span');s.className='sz';
   s.textContent=it.size>1048576?(it.size/1048576).toFixed(1)+' MB':(it.size/1024).toFixed(1)+' kB';r.append(s)}
  r.onclick=()=>it.dir?loadDir(d?d+'/'+it.name:it.name):loadFile(d?d+'/'+it.name:it.name);
  fl.append(r)})}
async function loadFile(p){const o=await api('file?p='+encodeURIComponent(p));
 if(o.error)return toast(o.error,1);
 openFile=p;$('#fname').textContent=p;$('#editor').value=o.content;
 $('#fdl').href='file?p='+encodeURIComponent(p)+'&raw=1';
 $('#fedit').style.display='block'}
$('#fsave').onclick=async()=>{if(openFile==null)return;
 const o=await api('file',{p:openFile,content:$('#editor').value});
 toast(o.ok?'saved (previous kept as .bak)':o.error,!o.ok)};

// ── backups ──
function renderBackups(){const tb=$('#bkList');tb.textContent='';
 S.backups.forEach(b=>{const tr=document.createElement('tr');
  const td1=document.createElement('td');td1.textContent=b.name;
  const td2=document.createElement('td');td2.textContent=(b.size/1048576).toFixed(0)+' MB';
  const td3=document.createElement('td');td3.textContent=new Date(b.ts*1000).toLocaleString();
  const td4=document.createElement('td');
  const dl=document.createElement('a');dl.className='act';dl.style.textDecoration='none';
  dl.style.padding='3px 9px';dl.textContent='download';dl.href='backup/dl?f='+encodeURIComponent(b.name);
  const del=document.createElement('button');del.className='act';del.textContent='delete';
  del.onclick=async()=>{if(!confirm('delete '+b.name+'?'))return;
   await api('backup/del',{f:b.name});refresh()};
  td4.append(dl,' ',del);tr.append(td1,td2,td3,td4);tb.append(tr)})}
$('#bkNow').onclick=async()=>{await api('backup',{});toast('backup started…')};

// ── settings ──
function renderSettings(){$('#setStart').value=S.start_cmd;$('#setKeep').value=S.keep_backups;
 sched=[...S.schedules];renderSched()}
function renderSched(){const el=$('#schedList');el.textContent='';
 if(!sched.length)el.innerHTML='<p class=sub>none</p>';
 sched.forEach((sc,i)=>{const r=document.createElement('div');r.className='row';
  const b=document.createElement('b');b.textContent=sc.time+' — '+sc.action;r.append(b);
  const x=document.createElement('button');x.className='act';x.textContent='remove';
  x.onclick=()=>{sched.splice(i,1);renderSched()};r.append(x);el.append(r)})}
$('#schedA').onchange=()=>{$('#schedC').style.display=$('#schedA').value==='custom'?'block':'none'};
$('#schedAdd').onclick=()=>{const t=$('#schedT').value;if(!t)return;
 const a=$('#schedA').value==='custom'?$('#schedC').value.trim():$('#schedA').value;
 if(!a)return;sched.push({time:t,action:a});renderSched()};
$('#setSave').onclick=async()=>{await api('settings',{start_cmd:$('#setStart').value,
 keep_backups:+$('#setKeep').value||5,schedules:sched});toast('settings saved')};
$('#pwBtn').onclick=async()=>{const o=await api('password',{old:$('#pwOld').value,new:$('#pwNew').value});
 toast(o.ok?'password changed — please sign in again':o.error,!o.ok);
 if(o.ok)setTimeout(()=>location='login',1200)};

// ── live events ──
let es=null;
function connect(){if(es)es.close();es=new EventSource('events');
 es.onopen=()=>refreshSoon();
 es.onmessage=m=>{const e=JSON.parse(m.data);
  if(e.type==='log')consLine(e.line);
  else if(e.type==='chat'||e.type==='join'||e.type==='leave'){
   const c=$('#chat'),stick=c.scrollTop+c.clientHeight>=c.scrollHeight-30;
   c.append(feedLine(e));while(c.childElementCount>400)c.firstChild.remove();
   if(stick)c.scrollTop=c.scrollHeight;
   if(e.type!=='chat')refreshSoon()}
  else if(e.type==='metric'){M.push(e);if(M.length>4400)M.shift();drawSparks()}
  else if(e.type==='status'){setDot(e.up);refreshSoon()}
  else if(e.type==='backup'){toast(e.msg,!e.ok);if(e.done)refreshSoon()}};
 // EventSource auto-retries, but if the server closed us as a slow consumer
 // force a fresh connection so we don't sit on a dead 'connecting' dot.
 es.onerror=()=>{setDot(null);if(es.readyState===2){es.close();refreshSoon();setTimeout(connect,3000)}}}
function setDot(up){$('#dot').className=up==null?'':up?'up':'down';
 $('#dot').title=up==null?'connecting':up?'online':'offline';
 $('#upinfo').textContent=up===false?'server offline':''}
let rT=null;const refreshSoon=()=>{clearTimeout(rT);rT=setTimeout(refresh,800)};
async function refresh(){const first=S==null;S=await api('state.json');M=S.metrics;
 setDot(S.up);renderFeed();renderLists();renderBackups();drawSparks();
 // Only (re)load Settings when the user isn't editing them — a passive refresh
 // from a join/backup event must not wipe an in-progress edit.
 if(first||!$('#set').classList.contains('on'))renderSettings();
 const c=$('#console');if(!c.childElementCount){S.console.forEach(l=>consLine(l))}}
refresh().then(()=>{connect();loadDir('')})
 .catch(()=>setTimeout(()=>location.reload(),3000));
window.addEventListener('resize',drawSparks);
</script>'''

# ── startup ──────────────────────────────────────────────────────────────
def read_props():
    props = {}
    try:
        for ln in open(SERVER_DIR / 'server.properties',
                       encoding='utf-8', errors='replace'):
            if '=' in ln and not ln.startswith('#'):
                k, v = ln.split('=', 1)
                props[k.strip()] = v.strip()
    except OSError:
        sys.exit(f'error: no server.properties in {SERVER_DIR}')
    return props

def init(args):
    global SERVER_DIR, STATE_PATH, BACKUP_DIR, LOG_PATH, RCON_ADDR, RCON_PW, NO_AUTH
    SERVER_DIR = Path(args.server_dir).resolve()
    STATE_PATH = SERVER_DIR / 'remora.json'
    BACKUP_DIR = SERVER_DIR / 'backups'
    LOG_PATH = SERVER_DIR / 'logs' / 'latest.log'
    NO_AUTH = args.no_auth
    props = read_props()
    if props.get('enable-rcon') != 'true':
        sys.exit('error: enable-rcon=true required in server.properties '
                 '(remora attaches via RCON)')
    RCON_ADDR = ('127.0.0.1', int(props.get('rcon.port', 25575)))
    RCON_PW = props.get('rcon.password', '')
    if not RCON_PW:   # Minecraft disables RCON entirely without a password
        sys.exit('error: rcon.password is empty in server.properties — set one '
                 'and restart the server (Minecraft disables RCON without it)')
    load_state()

def main():
    # line-buffer stdout: under systemd the generated first-run password was
    # printed into a block-buffered pipe that never flushed — new users got
    # locked out with no password anywhere in the journal.
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(
        description='remora — single-file web panel for a running Minecraft server')
    ap.add_argument('server_dir', help='server directory (with server.properties)')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--set-password', action='store_true',
                    help='set the admin password and exit')
    ap.add_argument('--no-auth', action='store_true',
                    help='disable built-in auth (ONLY behind an authenticating '
                         'reverse proxy)')
    args = ap.parse_args()
    init(args)

    if args.set_password:
        import getpass
        pw = getpass.getpass('new password: ') if sys.stdin.isatty() \
            else sys.stdin.readline().strip()
        if len(pw) < 8:
            sys.exit('min 8 characters')
        STATE['pw'] = hash_pw(pw)
        save_state()
        print('password set.')
        return

    if not NO_AUTH and 'pw' not in STATE:
        pw = secrets.token_urlsafe(9)
        STATE['pw'] = hash_pw(pw)
        save_state()
        print(f'* initial admin password: {pw}\n'
              f'  (change it in Settings, or rerun with --set-password)')

    load_history()
    for fn in (tail_loop, metrics_loop, scheduler_loop):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    print(f'remora {VERSION} on http://{args.host}:{args.port} -> {SERVER_DIR}'
          + (' [NO AUTH]' if NO_AUTH else ''))
    srv.serve_forever()

if __name__ == '__main__':
    main()
