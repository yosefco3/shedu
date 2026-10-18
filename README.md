# Shedu

**Shedu** (Akkadian *šēdu*): the winged guardian spirit that stood in pairs at the gates of Assyrian palaces.

A tiny, open-source security guard for small Linux servers. One command to install, zero
configuration, and it never blocks anything: it watches your server and tells you, on Telegram in plain
Hebrew or English, when something needs your attention.

```bash
curl -fsSL https://raw.githubusercontent.com/yosefco3/shedu/main/packaging/install.sh | sudo bash
```

## Who it is for

**Anyone who runs their own Linux server (a VPS) without a security person.** The server is yours,
so its security is too.

- **Indie developers** running a few projects on one cheap server.
- **Traders and bot operators**: the server holds API keys that are worth money, which makes it a target.
- **Small businesses** with a WordPress site or an app on a server someone set up once and nobody maintains.
- **Studios and freelancers** looking after several client servers.

Not for you if your app runs on a managed platform (Railway, Vercel, Render, Heroku): there is no
server of yours to watch, and the platform secures that layer.

## What it does

- **Health score (0–100)** — pending security updates, password logins over SSH, databases
  open to the internet, missing firewall, password-less accounts, bad file permissions.
  Every finding comes with a one-line explanation and a copy-pasteable fix.
- **Login watch** — brute-force attempts, a successful login from an address never seen
  before, a login right after a burst of failures.
- **Account watch** — new users, new SSH keys in any `authorized_keys`, changed sudo rights.
- **Behaviour watch** — programs running from `/tmp` or with their file deleted, a web server
  that suddenly opens a shell, likely crypto-miners, new cron jobs and systemd units,
  injected libraries (`ld.so.preload`, `LD_PRELOAD`), mass file changes in your web folder,
  and which program talks to which outside address (regular "beacons" are flagged).
- **Secrets and keys** — `.env`, `.git` and backups sitting in a public web folder, private
  keys others can read, passwords typed into shell history, and a list of every SSH key that
  can log in: whose it is, how old, when it was last used.
- **ClamAV**, if you already have it: a nightly scan, with an alert when something is found.
- **Daily report** to Telegram at 08:00, alerts within a minute.

One dial if it is too quiet or too noisy, in `/etc/shedu/guard.conf`:
`SENSITIVITY=low|normal|high` (default `normal`). You set how noisy Shedu is, not what is safe.

## Try it without installing

```bash
make build
sudo ./bin/shedu check            # terminal output is English
sudo ./bin/shedu check --lang he  # Hebrew (fine in a terminal that renders RTL)
sudo ./bin/shedu check --json
```

## Trust

- Single static Go binary, standard library only. Read every line.
- Report-only: the agent never changes the host. It writes only to `/var/lib/shedu`.
- **What leaves the server:** only the Telegram messages you configured, sent to
  `api.telegram.org` over TLS. No telemetry, no analytics, no third parties.
- Runs under systemd with `ProtectSystem=strict`, `NoNewPrivileges` and a 64 MB memory cap.
- Found a problem? See [SECURITY.md](SECURITY.md).

## Status

Phase 1 (the agent) and phase 2 (behaviour watch) are implemented. A central dashboard and
more are planned.

## License

Apache-2.0.
