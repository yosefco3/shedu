package i18n

var en = map[string]Msg{
	// --- checks ---
	"check.failed": {"The {{.name}} check could not run", "Shedu hit an error ({{.err}}) and skipped this check. The rest of the report is still valid."},

	"updates.security_pending":   {"{{.security}} security updates are waiting", "These fix holes that are already public, so attackers know about them too. This is the first thing an attacker checks. Packages include: {{.names}}."},
	"updates.pending":            {"{{.count}} updates are waiting", "No security fixes among them, but staying current keeps the next security update small and painless."},
	"updates.no_auto":            {"Security updates are not installed automatically", "Most break-ins use holes that were fixed weeks earlier. Let the server install security fixes by itself."},
	"updates.unsupported_distro": {"Update check skipped: not a Debian/Ubuntu system", "Shedu only knows apt for now. Other distributions come later."},

	"ssh.password_auth":   {"Anyone can try to log in with a password", "Robots try millions of passwords a day against every server on the internet. Key-only login closes that door. Make sure you log in with a key today, or the fix will lock you out."},
	"ssh.root_login":      {"Root can log in directly over SSH", "Attackers always try 'root' first. Let root in only with a key, or not at all."},
	"ssh.empty_passwords": {"SSH accepts empty passwords", "An account with no password can be entered by anyone. Turn this off now."},
	"ssh.max_auth_tries":  {"SSH allows many password guesses per connection", "Fewer attempts per connection slows brute-force robots down for free."},
	"ssh.x11_forwarding":  {"X11 forwarding is enabled", "Almost no server needs it. Turning it off removes one more attack path."},
	"ssh.need_root":       {"SSH settings could not be read", "Run shedu with sudo to audit the SSH configuration."},

	"ports.db_public":  {"Your {{.service}} (port {{.port}}) is open to the whole internet", "Databases and caches should only talk to the applications on this server. Exposed, they are found within minutes and are often unprotected by default. Bind it to 127.0.0.1 or block the port."},
	"ports.dev_public": {"A development-style port ({{.port}}) is open to the internet", "Ports like 3000 or 8080 usually run test servers without authentication. Make sure that is intended."},
	"ports.summary":    {"{{.count}} ports reachable from the internet: {{.list}}", "This is what the world sees. Everything listed here should be something you deliberately offer."},

	"firewall.none":             {"No firewall is filtering incoming traffic", "Every service on this server is reachable by anyone. A firewall lets only what you choose through."},
	"firewall.input_accept_all": {"A firewall exists but blocks nothing", "The rules are in place but the default is to let everything in. Enable ufw or add a drop policy."},
	"firewall.need_root":        {"Firewall state could not be read", "Run shedu with sudo to check the firewall."},

	"accounts.empty_password": {"User {{.user}} has no password", "Anyone who reaches a login prompt can enter as this user. Lock the account."},
	"accounts.uid0_extra":     {"User {{.user}} has root privileges (uid 0)", "Only 'root' should have uid 0. A second uid-0 user is a classic backdoor left by an intruder. Investigate before removing."},
	"accounts.sudo_nopasswd":  {"sudo without a password: {{.entry}}", "Whoever gets into this account becomes root instantly, no password needed. Require a password, or limit it to specific commands."},
	"accounts.need_root":      {"Account checks were partial", "Run shedu with sudo to audit passwords and sudo rights."},

	"perms.shadow_world_readable": {"The password file is readable by everyone", "/etc/shadow holds the password hashes of every user. Any process on the server can copy and crack them."},
	"perms.sshd_config_writable":  {"The SSH configuration can be modified by a non-root user", "Whoever edits it can open the server to themselves. It must belong to root and be writable by root only."},
	"perms.world_writable_etc":    {"{{.count}} system config files are writable by everyone", "Any user or hacked process can change them: {{.paths}}."},

	// --- alerts (watch) ---
	"alert.bruteforce":             {"🚨 Break-in attempt: {{.count}} failed logins from {{.ip}} in the last {{.minutes}} minutes", "Usernames tried: {{.users}}. Nobody got in. If password login is disabled this is just noise; if it is enabled, now is the time to disable it (run: sudo shedu check)."},
	"alert.login_new_ip":           {"New login: {{.user}} connected from {{.ip}}{{if .private}} (local network){{end}}", "This address has never logged in before (method: {{.method}}). If that was you, ignore this. If not, change passwords and check the SSH keys."},
	"alert.login_after_bruteforce": {"Someone logged in as {{.user}} from {{.ip}} right after guessing passwords", "{{.ip}} failed many times and then succeeded. Treat this as a break-in: lock the user, kill its sessions and rotate every secret on this server."},
	"alert.sudo_new_user":          {"{{.user}} used sudo for the first time", "Command: {{.command}}. Sudo makes anyone root. If you do not know this user, this is urgent."},
	"alert.sudo_fail":              {"{{.user}} tried sudo and failed", "{{.detail}}. Someone in this account is trying to become root."},
	"alert.user_added":             {"👤 New user created: {{.user}} (uid {{.uid}})", "If you did not create it, this is a backdoor. See when it last logged in, then remove it."},
	"alert.user_removed":           {"User removed: {{.user}}", "For your records."},
	"alert.key_added":              {"🔑 New SSH key for {{.user}}: {{.fp}} {{.comment}}", "A key is a permanent entrance without a password. If you did not add it, delete that line now."},
	"alert.key_removed":            {"SSH key removed for {{.user}}: {{.fp}}", "For your records."},
	"alert.sudoers_changed":        {"⚙️ sudo rights changed", "{{.diff}}"},
	"proc.tmp_exec":                {"A program is running from a temporary folder: {{.exe}}", "Process {{.comm}} (pid {{.pid}}, user {{.user}}) runs from {{.exe}}. Normal software almost never runs from /tmp, /var/tmp or /dev/shm, but malware droppers do. Command: {{.cmd}}"},
	"proc.deleted_exec":            {"A running program has no file on disk: {{.exe}}", "Process {{.comm}} (pid {{.pid}}, user {{.user}}) keeps running although its file was deleted. Malware does this to hide. The fix saves a copy for investigation, then stops it. Command: {{.cmd}}"},
	"proc.need_root":               {"Process checks were partial", "Run shedu with sudo to inspect every running program."},
	"alert.proc_tmp_exec":          {"🚨 A program is running from a temporary folder: {{.exe}}", "Process {{.comm}} (pid {{.pid}}, user {{.user}}). Normal software almost never runs from /tmp, /var/tmp or /dev/shm, but malware droppers do. Command: {{.cmd}}"},
	"alert.proc_deleted_exec":      {"🚨 A running program deleted its own file: {{.exe}}", "Process {{.comm}} (pid {{.pid}}, user {{.user}}) keeps running although its file is gone. Malware does this to hide. The fix saves a copy for investigation, then stops it. Command: {{.cmd}}"},
}
