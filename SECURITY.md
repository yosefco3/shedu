# Security policy

Shedu runs as root on your server, so we take reports seriously.

**Reporting a vulnerability:** open a private security advisory on GitHub
(Security → Report a vulnerability) or email the maintainer listed in the repository
profile. Please do not open a public issue for security problems. You will get an answer
within 72 hours.

**What the agent does and does not do**
- Reads: the system journal (sshd, sudo), `/etc/passwd`, `/etc/shadow` permissions,
  `authorized_keys` files, sudoers, `/proc/net/tcp`, apt and sshd configuration.
- Writes: only `/var/lib/shedu` (its state) and, through `install.sh`, `/etc/shedu`.
- Sends: only the Telegram messages you configured, to the Telegram Bot API over TLS.
  Nothing else leaves the server. No telemetry, no third parties.
- Never modifies firewall rules, users, keys, services or packages. Every "fix" is a
  command printed for you to run.

**Supported versions:** the latest release only.
