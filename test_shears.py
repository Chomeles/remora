#!/usr/bin/env python3
"""Self-check: fake RCON server + full wizard -> login -> panel flow. No deps."""
import os, socket, struct, tempfile, threading, urllib.request, http.cookiejar

os.environ['MCADMIN_DATA'] = tempfile.mkdtemp()
os.environ['MCADMIN_PORT'] = '18080'
os.environ['MCADMIN_BIND'] = '127.0.0.1'
import shears as mcadmin

RCON_PW = 'testpw'
ANSWERS = {'list': 'There are 1 of a max of 20 players online: Steve',
           'whitelist list': 'There are 1 whitelisted player(s): Steve',
           'banlist players': 'There are no bans'}


def fake_rcon(srv):
    while True:
        conn, _ = srv.accept()
        with conn:
            authed = False
            while True:
                try:
                    (length,) = struct.unpack('<i', conn.recv(4))
                    body = conn.recv(length)
                except (struct.error, ConnectionError):
                    break
                rid, ptype = struct.unpack('<ii', body[:8])
                payload = body[8:-2].decode()
                if ptype == 3:
                    authed = payload == RCON_PW
                    resp_id = rid if authed else -1
                    resp = ''
                else:
                    resp = ANSWERS.get(payload, '') if authed else ''
                    resp_id = rid
                out = struct.pack('<iii', 10 + len(resp), resp_id, 0 if ptype == 2 else 2) + resp.encode() + b'\x00\x00'
                conn.sendall(out)


srv = socket.create_server(('127.0.0.1', 18575))
threading.Thread(target=fake_rcon, args=(srv,), daemon=True).start()
threading.Thread(target=mcadmin.main, daemon=True).start()
import time; time.sleep(0.3)

jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
get = lambda path='/': op.open('http://127.0.0.1:18080' + path).read().decode()
post = lambda path, **data: op.open('http://127.0.0.1:18080' + path,
                                    urllib.parse.urlencode(data).encode()).read().decode()
import urllib.parse

# 1. wizard shows on first start
assert 'Setup' in get()
# 2. test button with wrong password fails
assert 'fehlgeschlagen' in post('/setup', do='test', user='a', pw='x' * 8, host='127.0.0.1', port='18575', rconpw='wrong')
# 3. test button with correct password succeeds
assert 'erfolgreich' in post('/setup', do='test', user='a', pw='x' * 8, host='127.0.0.1', port='18575', rconpw=RCON_PW)
# 4. save -> logged in, panel shows online player
assert 'Steve' in post('/setup', do='save', user='admin', pw='secret123', host='127.0.0.1', port='18575', rconpw=RCON_PW)
# 5. logout, then wrong login rejected
get('/logout')
assert 'Falsche' in post('/login', user='admin', pw='wrong')
# 6. correct login works
assert 'Steve' in post('/login', user='admin', pw='secret123')
# 7. console command round-trips
assert 'Ausgabe' in post('/', console='list')
# 8. config file has hashed pw, not plaintext admin pw
cfg = open(os.path.join(os.environ['MCADMIN_DATA'], 'config.json')).read()
assert 'secret123' not in cfg and 'pw_hash' in cfg

print('OK — alle 8 Checks bestanden')
