package watch

import "strings"

// serverComms are network-facing daemons that should never need an
// interactive shell. php-fpm shows up as php-fpm8.1 and similar. The php CLI
// (cron schedulers) and java (Jenkins) spawn shells for a living: not listed.
var serverComms = map[string]bool{
	"nginx": true, "apache2": true, "httpd": true, "php-fpm": true, "node": true,
	"gunicorn": true, "uwsgi": true, "caddy": true, "lighttpd": true, "puma": true, "php-cgi": true,
}

// shellComms are what an attacker gets out of a web exploit.
var shellComms = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "ksh": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true, "python3": true, "python": true, "perl": true,
}

func isServerComm(comm string) bool {
	if serverComms[comm] {
		return true
	}
	return strings.HasPrefix(comm, "php-fpm")
}

// SuspiciousLineage returns shells whose direct parent is a web/app server:
// the fingerprint of a webshell or remote code execution. Only the direct
// child is returned, so one break-in is one alert, not one per nested shell.
// PHP's mail() runs `sh -c /usr/sbin/sendmail`; that is skipped.
func SuspiciousLineage(procs []Process) []Process {
	byPID := make(map[int]Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	var out []Process
	for _, p := range procs {
		if !shellComms[p.Comm] {
			continue
		}
		parent, ok := byPID[p.PPID]
		if !ok || !isServerComm(parent.Comm) {
			continue
		}
		if strings.Contains(strings.Join(p.Cmdline, " "), "sendmail") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ParentComm returns the comm of p's parent, or "".
func ParentComm(procs []Process, p Process) string {
	for _, q := range procs {
		if q.PID == p.PPID {
			return q.Comm
		}
	}
	return ""
}
