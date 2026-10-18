// Package watch turns the host's login journal and account files into a stream
// of Events, and (step 09) Events into Alerts.
package watch

import (
	"context"
	"time"
)

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

	// phase 2 (behaviour watch)
	ProcSuspicious Kind = "proc_suspicious" // runs from /tmp-like dir, or deleted binary
	OutboundNew    Kind = "outbound_new"    // process talks to a destination not seen before
	PersistenceNew Kind = "persistence_new" // new or changed cron job / systemd unit
	ProcLineage    Kind = "proc_lineage"    // web server spawned a shell; mass file change
	PreloadChanged Kind = "preload_changed" // ld.so.preload or LD_PRELOAD
	MinerSuspected Kind = "miner_suspected" // sustained CPU + suspicious binary or pool port
)

// Event is one security-relevant thing that happened on the host.
type Event struct {
	Kind   Kind
	User   string
	IP     string // "" when local
	Method string // publickey | password | keyboard-interactive | ""
	Detail string // sudo command, key fingerprint, or the raw line
	Time   time.Time
	Args   map[string]string // phase-2 details (pid, exe, destination, ...) for the alert text
}

// Runner is a background watcher the daemon starts in its own goroutine.
// It owns its private state; save asks the daemon to persist the shared State.
type Runner interface {
	Run(ctx context.Context, st *State, out chan<- Event, save func() error)
}
