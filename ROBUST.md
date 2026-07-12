# Robustheits-Audit remora

Loop: alle 30 min eine Kategorie. Sandbox: Port 3197, Fake-RCON 3196 — nie der Live-Server.

- [x] Kaputte/böse HTTP-Requests — **BUG gefunden & gefixt:** POST mit `[]`/`null`/`"str"` als JSON-Body crashte den Handler (AttributeError auf `body.get`), Verbindung wurde ohne Antwort gedroppt. Fix: non-dict-JSON wird zu `{}` normalisiert → sauberes 4xx. Übrige Fälle ok: riesige Content-Length → 413, 200 Header → 431, 20k-Pfad → 401, Garbage → HTML, TRACE → 501, Server bleibt durchgehend erreichbar.
- [x] Auth/Session-Bypass — **kein Bug.** HMAC-Token (256-bit-Secret) end-to-end getestet: kein Cookie / Garbage / falsches Secret / manipuliertes exp / abgelaufen → alle 401, gültiges → 200; unauth POST auf `/cmd`/`/action`/`/password` wird nie ausgeführt (401); Secret rotiert bei Passwort-Änderung (invalidiert Alt-Sessions); `_ip()` vertraut X-Forwarded-For nur vom Loopback-Proxy und nimmt den angehängten letzten Eintrag.
- [ ] Path-Traversal im File-Editor
- [ ] RCON-Framing-Edge-Cases (Teilpakete, Riesenpakete, Verbindungsabbruch)
- [ ] Log-Parser: Unicode, kaputte Zeilen, rotierte gz-Logs
- [ ] Backup bei vollem Datenträger / laufendem Schreiben
- [ ] Scheduler-Randfälle
- [ ] Race-Conditions bei parallelen Requests
- [ ] Große Dateien im Editor
- [ ] remora.json korrupt/leer

**Deploy-Hinweis:** Fixes landen nur im Repo. Live-Instanz (/srv/remora, mc-remora.service) erst aktualisieren, wenn nicht gespielt wird.
