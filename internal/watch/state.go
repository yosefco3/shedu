package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// UserInfo is the part of a passwd entry worth remembering.
type UserInfo struct {
	UID   int    `json:"uid"`
	Shell string `json:"shell"`
	Home  string `json:"home"`
}

// AccountsSnapshot is what the accounts watcher (step 10) compares between runs.
type AccountsSnapshot struct {
	Users   map[string]UserInfo `json:"users"`   // name → info
	Keys    map[string][]string `json:"keys"`    // user → authorized-key fingerprints
	Sudoers string              `json:"sudoers"` // sha256 of all sudoers content
	Taken   time.Time           `json:"taken"`
}

// State is everything shedu remembers between restarts. Small, JSON, 0600.
type State struct {
	KnownIPs   map[string]time.Time `json:"known_ips"`   // ip → first successful login
	SudoUsers  map[string]time.Time `json:"sudo_users"`  // user → first sudo seen
	LastAlerts map[string]time.Time `json:"last_alerts"` // rate-limit key → last sent
	Accounts   AccountsSnapshot     `json:"accounts"`
}

const stateFile = "state.json"

func newState() *State {
	return &State{KnownIPs: map[string]time.Time{}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}}
}

// Fresh reports whether this state has never seen a login: the first run after install.
func (s *State) Fresh() bool { return len(s.KnownIPs) == 0 && s.Accounts.Taken.IsZero() }

// LoadState reads dir/state.json. Missing → empty state. Corrupt → the file is
// renamed to state.json.bad and an empty state is returned with a non-nil error
// the caller may log but need not treat as fatal.
func LoadState(dir string) (*State, error) {
	path := filepath.Join(dir, stateFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return newState(), err
	}
	st := newState()
	if err := json.Unmarshal(b, st); err != nil {
		_ = os.Rename(path, path+".bad")
		return newState(), fmt.Errorf("state.json was corrupt and moved aside: %w", err)
	}
	if st.KnownIPs == nil {
		st.KnownIPs = map[string]time.Time{}
	}
	if st.SudoUsers == nil {
		st.SudoUsers = map[string]time.Time{}
	}
	if st.LastAlerts == nil {
		st.LastAlerts = map[string]time.Time{}
	}
	return st, nil
}

// Save writes atomically (tmp + rename) with mode 0600; dir is created 0700.
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}
