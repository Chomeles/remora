#!/usr/bin/env python3
"""shears — single-file Minecraft admin panel. RCON-only, works with any server.
Python 3.9+, stdlib only. First start opens a setup wizard in the browser."""
import hashlib, hmac, html, json, os, re, secrets, socket, struct, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

DATA_DIR = os.environ.get('MCADMIN_DATA', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')
BIND = os.environ.get('MCADMIN_BIND', '0.0.0.0')
PORT = int(os.environ.get('MCADMIN_PORT', '8080'))
NAME_RE = re.compile(r'^\.?[A-Za-z0-9_ ]{1,20}$')

config = None          # dict once wizard is done
sessions = {}          # token -> expiry (in-memory; re-login after restart is fine)
lock = threading.Lock()


def load_config():
    global config
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config = None


def save_config(cfg):
    global config
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CONFIG_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PATH)
    config = cfg


def hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200_000).hex()
    return salt, h


def check_pw(password, salt, expected):
    return hmac.compare_digest(hash_pw(password, salt)[1], expected)


# ---------- RCON (Source RCON protocol, works with every MC server) ----------
class RconError(Exception):
    pass


def rcon(command, host=None, port=None, password=None):
    host = host or config['rcon_host']
    port = port or config['rcon_port']
    password = password if password is not None else config['rcon_password']

    def send(sock, req_id, ptype, payload):
        data = struct.pack('<iii', 10 + len(payload), req_id, ptype) + payload.encode() + b'\x00\x00'
        sock.sendall(data)

    def recv(sock):
        raw = b''
        while len(raw) < 4:
            chunk = sock.recv(4 - len(raw))
            if not chunk:
                raise RconError('Verbindung geschlossen')
            raw += chunk
        (length,) = struct.unpack('<i', raw)
        body = b''
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                raise RconError('Verbindung geschlossen')
            body += chunk
        rid, rtype = struct.unpack('<ii', body[:8])
        return rid, rtype, body[8:-2].decode(errors='replace')

    try:
        with socket.create_connection((host, port), timeout=5) as s:
            send(s, 1, 3, password)
            rid, _, _ = recv(s)
            if rid == -1:
                raise RconError('RCON-Passwort falsch')
            send(s, 2, 2, command)
            _, _, text = recv(s)
            return re.sub('§.', '', text)
    except (OSError, struct.error) as e:
        raise RconError(f'Keine Verbindung zu {host}:{port} ({e})')


def names_after_colon(out):
    if ':' not in out:
        return []
    return [n.strip() for n in out.split(':', 1)[1].split(',') if n.strip()]


# ---------- HTML ----------
STYLE = '''<style>
body{font:15px system-ui;background:#111;color:#eee;max-width:680px;margin:2em auto;padding:0 1em}
h1{font-size:1.3em}h2{font-size:1em;color:#8f8;border-bottom:1px solid #333;padding-bottom:4px}
.row{display:flex;gap:8px;align-items:center;padding:5px 0}.row b{flex:1}.dim{color:#666}
form{margin:0}input,select{background:#222;color:#eee;border:1px solid #444;border-radius:6px;padding:6px 8px}
button{background:#2a4;color:#fff;border:0;border-radius:6px;padding:6px 12px;cursor:pointer}
button.sec{background:#222;border:1px solid #444}button:hover{filter:brightness(1.2)}
.err{color:#f77}.ok{color:#8f8}.card{background:#1a1a1a;border:1px solid #333;border-radius:10px;padding:1em 1.5em;margin:1em 0}
label{display:block;margin:.8em 0 .2em;color:#aaa}pre{background:#000;padding:.7em;border-radius:6px;overflow-x:auto;white-space:pre-wrap}
</style>'''


def doc(title, body):
    return (f'<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
            f'<title>{title}</title>{STYLE}{body}').encode()


def wizard_page(err='', ok=''):
    msg = f'<p class=err>{html.escape(err)}</p>' if err else (f'<p class=ok>{html.escape(ok)}</p>' if ok else '')
    return doc('shears Setup', f'''<h1>✂️ shears — Setup</h1><div class=card>
<form method=post action=/setup>{msg}
<h2>1. Admin-Konto</h2>
<label>Benutzername</label><input name=user required maxlength=32>
<label>Passwort (min. 8 Zeichen)</label><input name=pw type=password required minlength=8>
<h2>2. Minecraft-Server (RCON)</h2>
<p class=dim>In der <code>server.properties</code>: <code>enable-rcon=true</code>, <code>rcon.port</code>, <code>rcon.password</code> setzen und Server neu starten.</p>
<label>Host</label><input name=host value=localhost required>
<label>RCON-Port</label><input name=port value=25575 required pattern="[0-9]+">
<label>RCON-Passwort</label><input name=rconpw type=password required>
<p style="margin-top:1em"><button name=do value=test class=sec>🔌 Verbindung testen</button>
<button name=do value=save>✅ Speichern &amp; loslegen</button></p></form></div>''')


def login_page(err=''):
    msg = f'<p class=err>{html.escape(err)}</p>' if err else ''
    return doc('shears Login', f'''<h1>✂️ shears</h1><div class=card><form method=post action=/login>{msg}
<label>Benutzername</label><input name=user autofocus>
<label>Passwort</label><input name=pw type=password>
<p style="margin-top:1em"><button>Anmelden</button></p></form></div>''')


def btns(name, *acts):
    labels = {'whitelist add': '✅ whitelist', 'whitelist remove': '❌ entfernen',
              'kick': '👢 kick', 'ban': '🔨 ban', 'pardon': '🕊️ entbannen'}
    f = ''.join(f'<form method=post><input type=hidden name=name value="{html.escape(name)}">'
                f'<button class=sec name=cmd value="{a}">{labels[a]}</button></form>' for a in acts)
    return f'<div class=row><b>{html.escape(name)}</b>{f}</div>'


def panel_page(console_out=''):
    try:
        online = names_after_colon(rcon('list'))
        wl = names_after_colon(rcon('whitelist list'))
        banned = re.findall(r'([A-Za-z0-9_.]{1,20}) was banned', rcon('banlist players'))
        err = ''
    except RconError as e:
        online, wl, banned = [], [], []
        err = f'<p class=err>⚠️ {html.escape(str(e))}</p>'
    sec = lambda title, rows: f'<h2>{title}</h2>' + (''.join(rows) or '<p class=dim>—</p>')
    out = f'<h2>⌨️ Ausgabe</h2><pre>{html.escape(console_out)}</pre>' if console_out else ''
    return doc('shears', f'''<h1>✂️ shears <a href=/logout style="float:right;font-size:.6em;color:#888">abmelden</a></h1>{err}
{sec('🟢 Online', [btns(n, 'kick', 'ban') for n in online])}
{sec('📋 Whitelist', [btns(n, 'whitelist remove', 'ban') for n in wl])}
{sec('🚫 Gebannt', [btns(n, 'pardon') for n in banned])}
<h2>➕ Spieler zur Whitelist</h2>
<form method=post class=row><input name=name maxlength=21 placeholder="Spielername" style=flex:1>
<input type=hidden name=cmd value="whitelist add"><button>hinzufügen</button></form>
<h2>📢 Broadcast</h2>
<form method=post class=row><input name=say maxlength=256 placeholder="Nachricht an alle…" style=flex:1><button>senden</button></form>
<h2>⌨️ Konsole</h2>
<form method=post class=row><input name=console maxlength=256 placeholder="Befehl, z.B. time set day" style=flex:1><button>ausführen</button></form>
{out}<p class=dim style="margin-top:2em">shears · <a href="https://github.com/Chomeles/shears" style=color:#888>GitHub</a></p>''')


# ---------- HTTP ----------
class H(BaseHTTPRequestHandler):
    server_version = 'shears'

    def reply(self, body, status=200, headers=()):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, loc, headers=()):
        self.send_response(303)
        self.send_header('Location', loc)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def form(self):
        length = int(self.headers.get('Content-Length', 0))
        if length > 65536:
            return {}
        q = urllib.parse.parse_qs(self.rfile.read(length).decode(errors='replace'))
        return {k: v[0] for k, v in q.items()}

    def logged_in(self):
        c = SimpleCookie(self.headers.get('Cookie', ''))
        tok = c['s'].value if 's' in c else ''
        with lock:
            exp = sessions.get(tok)
            if exp and exp > time.time():
                return True
            sessions.pop(tok, None)
        return False

    def new_session(self):
        tok = secrets.token_urlsafe(32)
        with lock:
            sessions[tok] = time.time() + 30 * 86400
        return ('Set-Cookie', f's={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age={30*86400}')

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if config is None:
            return self.reply(wizard_page())
        if path == '/logout':
            c = SimpleCookie(self.headers.get('Cookie', ''))
            with lock:
                sessions.pop(c['s'].value if 's' in c else '', None)
            return self.redirect('/', [('Set-Cookie', 's=; Path=/; Max-Age=0')])
        if not self.logged_in():
            return self.reply(login_page())
        self.reply(panel_page())

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        f = self.form()
        if config is None:
            return self.wizard_submit(f)
        if path == '/login':
            if (f.get('user') == config['user']
                    and check_pw(f.get('pw', ''), config['salt'], config['pw_hash'])):
                return self.redirect('/', [self.new_session()])
            time.sleep(1)  # ponytail: global 1s brake against brute force; rate-limit per IP if it ever matters
            return self.reply(login_page('Falsche Zugangsdaten.'))
        if not self.logged_in():
            return self.reply(login_page())
        return self.action(f)

    def wizard_submit(self, f):
        try:
            host, port, rconpw = f.get('host', ''), int(f.get('port', '0')), f.get('rconpw', '')
            rcon('list', host, port, rconpw)
        except (ValueError, RconError) as e:
            return self.reply(wizard_page(err=f'Verbindung fehlgeschlagen: {e}'))
        if f.get('do') == 'test':
            return self.reply(wizard_page(ok='✅ Verbindung erfolgreich! Jetzt speichern.'))
        user, pw = f.get('user', '').strip(), f.get('pw', '')
        if not user or len(pw) < 8:
            return self.reply(wizard_page(err='Benutzername fehlt oder Passwort zu kurz (min. 8).'))
        salt, pw_hash = hash_pw(pw)
        save_config({'user': user, 'salt': salt, 'pw_hash': pw_hash,
                     'rcon_host': host, 'rcon_port': port, 'rcon_password': rconpw})
        self.redirect('/', [self.new_session()])

    def action(self, f):
        try:
            if f.get('say', '').strip():
                rcon('say ' + f['say'].replace('\n', ' ').strip()[:256])
            elif f.get('console', '').strip():
                out = rcon(f['console'].strip()[:256])
                return self.reply(panel_page(console_out=out or '(keine Ausgabe)'))
            elif f.get('cmd') in ('whitelist add', 'whitelist remove', 'kick', 'ban', 'pardon'):
                name, cmd = f.get('name', '').strip(), f['cmd']
                if NAME_RE.match(name):
                    # Bedrock/Floodgate names (dot prefix) need fwhitelist
                    if name.startswith('.') and cmd.startswith('whitelist'):
                        cmd, name = cmd.replace('whitelist', 'fwhitelist'), name[1:]
                    rcon(f'{cmd} {name}')
        except RconError:
            pass  # panel shows the connection error banner
        self.redirect('/')

    def log_message(self, *a):
        pass


def main():
    load_config()
    print(f'shears läuft auf http://{BIND}:{PORT}' + ('' if config else ' — Setup-Wizard im Browser öffnen'))
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()


if __name__ == '__main__':
    main()
