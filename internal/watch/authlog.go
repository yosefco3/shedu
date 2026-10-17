package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Source produces Events until ctx is cancelled or the underlying source ends,
// then closes the channel. The daemon restarts a source that ends early.
type Source interface {
	Events(ctx context.Context) (<-chan Event, error)
}

// NewSource picks journald when journalctl exists, else the classic auth.log.
func NewSource() Source {
	if _, err := exec.LookPath("journalctl"); err == nil {
		return &Journal{}
	}
	return &FileTail{Path: "/var/log/auth.log"}
}

var (
	// program tag and the message after it; works for syslog files and bare journal MESSAGEs
	reProgram  = regexp.MustCompile(`(?:^|\s)(sshd|sshd-session|sudo)(?:\[\d+\])?:\s*(.*)$`)
	reAccepted = regexp.MustCompile(`^Accepted (publickey|password|keyboard-interactive(?:/pam)?) for (\S+) from (\S+) port`)
	reFailed   = regexp.MustCompile(`^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for (invalid user )?(\S+) from (\S+) port`)
	reInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	reSudoCmd  = regexp.MustCompile(`^\s*(\S+) : (?:TTY|PWD).*COMMAND=(.*)$`)
	reSudoFail = regexp.MustCompile(`^\s*(\S+) : (\d+ incorrect password attempts|user NOT in sudoers|command not allowed)`)
	reSyslogTS = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s`)
	reISOTS    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:\d{2}|Z)?\s`)
)

// ParseAuthLine parses one sshd/sudo line, with or without the syslog prefix.
// ok is false for lines we do not care about.
func ParseAuthLine(line string, now time.Time) (Event, bool) {
	ts := parseTimestamp(line, now)
	msg := line
	if m := reProgram.FindStringSubmatch(line); m != nil {
		msg = m[2]
	}
	msg = strings.TrimSpace(msg)
	switch {
	case strings.HasPrefix(msg, "Accepted "):
		if m := reAccepted.FindStringSubmatch(msg); m != nil {
			return Event{Kind: LoginOK, Method: strings.TrimSuffix(m[1], "/pam"), User: m[2], IP: m[3], Time: ts, Detail: msg}, true
		}
	case strings.HasPrefix(msg, "Failed "):
		if m := reFailed.FindStringSubmatch(msg); m != nil {
			return Event{Kind: LoginFail, User: m[2], IP: m[3], Time: ts, Detail: msg}, true
		}
	case strings.HasPrefix(msg, "Invalid user "):
		if m := reInvalid.FindStringSubmatch(msg); m != nil {
			return Event{Kind: InvalidUser, User: m[1], IP: m[2], Time: ts, Detail: msg}, true
		}
	default:
		if m := reSudoFail.FindStringSubmatch(msg); m != nil {
			return Event{Kind: SudoFail, User: m[1], Time: ts, Detail: m[2]}, true
		}
		if m := reSudoCmd.FindStringSubmatch(msg); m != nil {
			return Event{Kind: SudoCmd, User: m[1], Time: ts, Detail: strings.TrimSpace(m[2])}, true
		}
	}
	return Event{}, false
}

func parseTimestamp(line string, now time.Time) time.Time {
	if m := reISOTS.FindStringSubmatch(line); m != nil {
		layout := "2006-01-02T15:04:05"
		s := m[1]
		if m[2] != "" {
			layout += "Z07:00"
			s += m[2]
		}
		if t, err := time.ParseInLocation(layout, s, now.Location()); err == nil {
			return t
		}
	}
	if m := reSyslogTS.FindStringSubmatch(line); m != nil {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", m[1], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // log line from last December, read in January
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return now
}

type journalLine struct {
	Message    json.RawMessage `json:"MESSAGE"`
	Identifier string          `json:"SYSLOG_IDENTIFIER"`
	Comm       string          `json:"_COMM"`
	Realtime   string          `json:"__REALTIME_TIMESTAMP"`
}

var wantedPrograms = map[string]bool{"sshd": true, "sshd-session": true, "sudo": true}

// ParseJournalLine parses one `journalctl -o json` record.
func ParseJournalLine(line []byte) (Event, bool) {
	var j journalLine
	if err := json.Unmarshal(line, &j); err != nil {
		return Event{}, false
	}
	if !wantedPrograms[j.Identifier] && !wantedPrograms[j.Comm] {
		return Event{}, false
	}
	var msg string
	if err := json.Unmarshal(j.Message, &msg); err != nil {
		return Event{}, false // binary MESSAGE (byte array): not ours
	}
	now := time.Now()
	if us, err := strconv.ParseInt(j.Realtime, 10, 64); err == nil {
		now = time.UnixMicro(us)
	}
	ev, ok := ParseAuthLine(msg, now)
	if ok {
		ev.Time = now
	}
	return ev, ok
}

// Journal follows journald for sshd and sudo records.
type Journal struct {
	// Command overrides the journalctl invocation (tests).
	Command func(ctx context.Context) *exec.Cmd
}

func (j *Journal) Events(ctx context.Context) (<-chan Event, error) {
	mk := j.Command
	if mk == nil {
		mk = func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "journalctl", "-o", "json", "-f", "-n", "0",
				"-t", "sshd", "-t", "sshd-session", "-t", "sudo")
		}
	}
	cmd := mk(ctx)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ch := make(chan Event, 64)
	go func() {
		defer close(ch)
		defer cmd.Wait()
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if ev, ok := ParseJournalLine(sc.Bytes()); ok {
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}

// FileTail follows a syslog-style file (auth.log), surviving rotation.
type FileTail struct {
	Path string
	Poll time.Duration // default 1s
	Now  func() time.Time
}

func (f *FileTail) Events(ctx context.Context) (<-chan Event, error) {
	if _, err := os.Stat(f.Path); err != nil {
		return nil, err
	}
	lines, err := TailLines(ctx, f.Path, f.Poll)
	if err != nil {
		return nil, err
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}
	ch := make(chan Event, 64)
	go func() {
		defer close(ch)
		for line := range lines {
			if ev, ok := ParseAuthLine(line, now()); ok {
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, nil
}
