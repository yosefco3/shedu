# Shedu

**Shedu** (Akkadian *šēdu*): the winged guardian spirit that stood in pairs at the gates of Assyrian palaces.

A tiny, open-source security guard for small Linux servers. One command to install, zero
configuration, and it never blocks anything: it watches your server and tells you, on Telegram in plain
Hebrew or English, when something needs your attention.

```bash
curl -fsSL https://raw.githubusercontent.com/yosefco3/shedu/main/packaging/install.sh | sudo bash
```

## What it does

- **Health score (0–100)** — pending security updates, password logins over SSH, databases
  open to the internet, missing firewall, password-less accounts, bad file permissions.
  Every finding comes with a one-line explanation and a copy-pasteable fix.
- **Login watch** — brute-force attempts, a successful login from an address never seen
  before, a login right after a burst of failures.
- **Account watch** — new users, new SSH keys in any `authorized_keys`, changed sudo rights.
- **Daily report** to Telegram at 08:00, alerts within a minute.

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
- Nothing leaves the server except the Telegram messages you configured.
- Runs under systemd with `ProtectSystem=strict`, `NoNewPrivileges` and a 64 MB memory cap.

## Status

Phase 1 (the agent) is implemented and released. A central dashboard, behaviour detection
and more are planned.

## License

Apache-2.0.
