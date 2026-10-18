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
- Writes: only `/var/lib/shedu` (its state) and, through `install.sh`, `/etc/shedu`.
- Sends: only the Telegram messages you configured, to the Telegram Bot API over TLS.
  Nothing else leaves the server. No telemetry, no third parties. Alerts can contain
  usernames, IP addresses, file paths, process names and command lines from your server,
  so treat the Telegram chat as private.
- Never modifies firewall rules, users, keys, services or packages. Every "fix" is a
  command printed for you to run.

**Supported versions:** the latest release only.
