// Package watch turns the host's login journal and account files into a stream
// of Events, and (step 09) Events into Alerts.
package watch

import "time"

// Kind names what happened.
type Kind string

const (
	LoginOK        Kind = "login_ok"        // Accepted <method> for U from IP
	LoginFail      Kind = "login_fail"      // Failed password for [invalid user] U from IP
	InvalidUser    Kind = "invalid_user"    // Invalid user U from IP
	SudoCmd        Kind = "sudo"            // U : TTY=... ; COMMAND=...
	SudoFail       Kind = "sudo_fail"       // incorrect password attempts / NOT in sudoers
	UserAdded      Kind = "user_added"      // step 10
	UserRemoved    Kind = "user_removed"    // step 10
	KeyAdded       Kind = "key_added"       // step 10
	KeyRemoved     Kind = "key_removed"     // step 10
	SudoersChanged Kind = "sudoers_changed" // step 10
)

// Event is one security-relevant thing that happened on the host.
type Event struct {
	Kind   Kind
	User   string
	IP     string // "" when local
	Method string // publickey | password | keyboard-interactive | ""
	Detail string // sudo command, key fingerprint, or the raw line
	Time   time.Time
}
