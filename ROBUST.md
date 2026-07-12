# Robustheits-Audit remora

Loop: alle 30 min eine Kategorie. Sandbox: Port 3197, Fake-RCON 3196 — nie der Live-Server.

- [x] Kaputte/böse HTTP-Requests — **BUG gefunden & gefixt:** POST mit `[]`/`null`/`"str"` als JSON-Body crashte den Handler (AttributeError auf `body.get`), Verbindung wurde ohne Antwort gedroppt. Fix: non-dict-JSON wird zu `{}` normalisiert → sauberes 4xx. Übrige Fälle ok: riesige Content-Length → 413, 200 Header → 431, 20k-Pfad → 401, Garbage → HTML, TRACE → 501, Server bleibt durchgehend erreichbar.
- [x] Auth/Session-Bypass — **kein Bug.** HMAC-Token (256-bit-Secret) end-to-end getestet: kein Cookie / Garbage / falsches Secret / manipuliertes exp / abgelaufen → alle 401, gültiges → 200; unauth POST auf `/cmd`/`/action`/`/password` wird nie ausgeführt (401); Secret rotiert bei Passwort-Änderung (invalidiert Alt-Sessions); `_ip()` vertraut X-Forwarded-For nur vom Loopback-Proxy und nimmt den angehängten letzten Eintrag.
- [x] Path-Traversal im File-Editor — **kein Bug.** `safe_path` (unit-getestet) end-to-end an allen drei Endpunkten bestätigt: Lesen/Auflisten/**Schreiben** weisen `../`, URL-kodierte Traversal, absolute Pfade, Symlink-Escape und `remora.json` alle mit 400 ab; nichts wird außerhalb von SERVER_DIR geschrieben, State-Datei bleibt unverändert, legitime In-Tree-Writes funktionieren weiter.
- [x] RCON-Framing-Edge-Cases — **kein Bug.** `rcon()` gegen 8 bösartige Fake-Server geprüft: byteweise fragmentierte Antwort wird korrekt reassembliert; hängender Server (nie antwortend) läuft sauber in den 2s-Timeout und gibt `None` — **und der Folge-Call beweist, dass RCON_LOCK freigegeben wird** (kein Wedge des Panels); 100-MB-Länge, Mini-/Negativ-Länge, Mid-Stream-Abbruch, Auth-Fail (rid=-1) und HTTP auf dem Port geben alle sofort `None` ohne Crash.
- [ ] Log-Parser: Unicode, kaputte Zeilen, rotierte gz-Logs
- [ ] Backup bei vollem Datenträger / laufendem Schreiben
- [ ] Scheduler-Randfälle
- [ ] Race-Conditions bei parallelen Requests
- [ ] Große Dateien im Editor
- [ ] remora.json korrupt/leer

**Deploy-Hinweis:** Fixes landen nur im Repo. Live-Instanz (/srv/remora, mc-remora.service) erst aktualisieren, wenn nicht gespielt wird.
