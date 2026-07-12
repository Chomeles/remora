# ✂️ shears

**A dead-simple web admin panel for any Minecraft server.** One file, zero dependencies, browser setup wizard. Works with Vanilla, Paper, Spigot, Fabric, Purpur — anything with RCON.

![panel](docs/screenshot.png)

## Features

- 🟢 See who's online — kick or ban with one click
- 📋 Manage the whitelist (add / remove / ban)
- 🚫 Ban list with one-click pardon
- 📢 Broadcast messages to all players
- ⌨️ Run any console command from the browser
- 🧭 Bedrock/Geyser support: names starting with `.` are routed to `fwhitelist` (Floodgate)
- 🔒 Built-in login (no reverse proxy needed), password stored hashed (PBKDF2)
- 🪄 First start = setup wizard in the browser. No config files to edit.

## Quick start

### Docker (recommended)

```bash
docker run -d -p 8080:8080 -v shears:/data --name shears ghcr.io/chomeles/shears
```

### Without Docker

Needs only Python 3.9+ — no pip packages:

```bash
curl -O https://raw.githubusercontent.com/Chomeles/shears/main/shears.py
python3 shears.py
```

Then open **http://localhost:8080** and follow the wizard.

## Enable RCON on your Minecraft server

In your server's `server.properties`:

```properties
enable-rcon=true
rcon.port=25575
rcon.password=choose-a-strong-password
```

Restart the server once. That's it — the wizard has a "Test connection" button.

> If the panel runs on a different machine than the server, make sure the RCON port is reachable (but **never** expose RCON to the public internet — use a private network, VPN, or run the panel on the same host).

## Configuration

Everything is set up through the wizard and stored in `data/config.json`. Optional environment variables:

| Variable | Default | |
|---|---|---|
| `MCADMIN_PORT` | `8080` | HTTP port |
| `MCADMIN_BIND` | `0.0.0.0` | Bind address |
| `MCADMIN_DATA` | `./data` | Config directory |

To reset everything (password forgotten, wrong server): delete `data/config.json` and restart — the wizard reappears.

## HTTPS

Put it behind any reverse proxy (Caddy, nginx, Traefik) or a tunnel (Cloudflare Tunnel, Tailscale). Example Caddyfile:

```
mc.example.com {
    reverse_proxy localhost:8080
}
```

## License

MIT
