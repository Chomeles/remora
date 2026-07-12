# Robustheits-Audit remora

Loop: alle 30 min eine Kategorie. Sandbox: Port 3197, Fake-RCON 3196 — nie der Live-Server.

- [x] Kaputte/böse HTTP-Requests — **BUG gefunden & gefixt:** POST mit `[]`/`null`/`"str"` als JSON-Body crashte den Handler (AttributeError auf `body.get`), Verbindung wurde ohne Antwort gedroppt. Fix: non-dict-JSON wird zu `{}` normalisiert → sauberes 4xx. Übrige Fälle ok: riesige Content-Length → 413, 200 Header → 431, 20k-Pfad → 401, Garbage → HTML, TRACE → 501, Server bleibt durchgehend erreichbar.
- [ ] Auth/Session-Bypass
- [ ] Path-Traversal im File-Editor
- [ ] RCON-Framing-Edge-Cases (Teilpakete, Riesenpakete, Verbindungsabbruch)
- [ ] Log-Parser: Unicode, kaputte Zeilen, rotierte gz-Logs
- [ ] Backup bei vollem Datenträger / laufendem Schreiben
- [ ] Scheduler-Randfälle
- [ ] Race-Conditions bei parallelen Requests
- [ ] Große Dateien im Editor
- [ ] remora.json korrupt/leer

**Deploy-Hinweis:** Fixes landen nur im Repo. Live-Instanz (/srv/remora, mc-remora.service) erst aktualisieren, wenn nicht gespielt wird.
