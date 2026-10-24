# Security policy

Shedu runs as root on your server, so we take reports seriously.

**Reporting a vulnerability:** open a private security advisory on GitHub
(Security → Report a vulnerability) or email the maintainer listed in the repository
profile. Please do not open a public issue for security problems. You will get an answer
within 72 hours.

**What the agent does and does not do**
- Reads: the system journal (sshd, sudo), `/etc/passwd`, `/etc/shadow` permissions,
  `authorized_keys` files, sudoers, `/proc/net/tcp`, apt and sshd configuration.
- Behaviour watch reads: the process list in `/proc` (program path, command line, parent,
  CPU time, open sockets), each process's environment once, only to look for
  `LD_PRELOAD`, cron and systemd unit files, `/etc/ld.so.preload`, and file names and
  modification times in web folders.
- Secret checks read: file names in web folders, `~/.ssh` permissions, and shell history
  files. History lines are matched against patterns on the server. **Only the file name
  is ever reported, never the matched text or any secret value.**
- Optionally runs ClamAV, if it is already installed, on a nightly schedule.
- Writes: only `/var/lib/shedu` (its state) and its config file, `/etc/shedu/guard.conf` by
  default (through `install.sh`, and through `shedu enroll`, which adds or removes `CLOUD_URL`
  and `CLOUD_KEY` via a temporary file in the same folder that replaces the old one).
- Sends: the Telegram messages you configured, to the Telegram Bot API over TLS, and, only
  if you enrolled the server, the reports described below to Shedu Cloud. Nothing else
  leaves the server. No telemetry, no third parties. Alerts can contain usernames, IP
  addresses, file paths, process names and command lines from your server, so treat the
  Telegram chat and your cloud account as private.
- Never modifies firewall rules, users, keys, services or packages. Every "fix" is a
  command printed for you to run.

**What the agent sends to Shedu Cloud (optional)**

Shedu Cloud (`https://app.getshedu.com`) is an optional dashboard for all your servers, with
alerts by email and by the official Telegram bot. It is off unless you enroll the server
(`install.sh --cloud <token>` or `sudo shedu enroll <token>`). Without a `CLOUD_KEY` in
`/etc/shedu/guard.conf` the agent makes no request to the cloud at all.

- **The message types are declared in [`pkg/cloudapi`](pkg/cloudapi)**, the public schema; the
  agent sends nothing outside them. In short:
  - at enrollment: hostname, operating system name, CPU architecture, agent version;
  - reports (at start-up, daily, after `shedu check`): host name, time, score, agent version,
    exactly what `shedu check --json` prints for each finding (id, severity, arguments, fix
    command, evidence), the same texts in Hebrew and English, and the TCP ports reachable from
    outside (port, protocol, bind address, process name);
  - alerts: the same alerts that go to Telegram (id, severity, arguments, fix, texts, time),
    with a unique id;
  - a heartbeat every 5 minutes: time, agent version, uptime, which watchers run, whether
    direct Telegram is configured, the server's interface addresses, the language.
- **Arguments and evidence are free text from your server**, the same as in the Telegram
  alerts: for example the first 200 characters of a flagged process's command line, a
  configuration line, a sudoers line, a key fingerprint, a file path, or firewall rules.
  Whatever was typed on a flagged command line (a password passed as an argument, say)
  can therefore be in it.
- **Never sent:** the full process list, the connection table, private key material, the
  contents of files that the secret checks look at, and shell history lines (history and
  secret findings carry the file path only).
- **Outbound only, and no command channel.** The agent opens HTTPS connections to
  `api.getshedu.com` (system CA store); it refuses a plain-http `CLOUD_URL` except to
  localhost, so the key never travels in clear text. Nothing connects to the server. Apart
  from the address and key returned once at enrollment (which `shedu enroll` stores), the
  cloud's answers are display-only data (for example "a newer version exists"), and the
  agent never acts on them. **The cloud can never execute anything on your server**: there is
  no code path for it. As an extra guard, a test (`TestNoCommandFields`, part of `go test`,
  which every release runs) fails if an answer type gains a field whose name looks like an
  instruction. A break-in at the cloud gives no control over enrolled servers.
- **Key:** enrollment trades a one-time token for a per-server key (`shk_…`). The cloud
  stores only its SHA-256. The key sits in `/etc/shedu/guard.conf` (mode 0600) and is never
  logged; each request is one line in the journal (`cloud: POST /v1/events 200`), without
  body or key.
- **Turning it off:** `sudo shedu enroll --off && sudo systemctl restart shedu`. The journal
  then shows `cloud: off` and the agent behaves exactly as without the cloud. Deleting the
  server in the dashboard removes its reports and alerts from the cloud.
- While enrolled, alerts are sent by the cloud. A directly configured Telegram bot is used
  only as a fallback when the cloud has been unreachable for 10 minutes, so each alert
  arrives once.

**Release integrity:** release binaries are built with `CGO_ENABLED=0`, `-trimpath`,
`-buildvcs=false` and an empty build id, so the same tag built with the same Go version gives
the same bytes. `go version shedu_linux_amd64` prints that Go version; rebuild with it and
compare with `SHA256SUMS`:

    git checkout vX.Y.Z
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=vX.Y.Z" -o shedu_linux_amd64 ./cmd/shedu
    sha256sum shedu_linux_amd64

`install.sh` checks every downloaded release against `SHA256SUMS` (not when you pass
`--binary`). Releases are **not signed yet**. Once they are, `SHA256SUMS.minisig` is published
next to each release, its public key is printed in the README and baked into `install.sh`,
and `install.sh` then refuses a release without a valid signature whenever `minisign` is
installed.

**Supported versions:** the latest release only.
