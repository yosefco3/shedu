package watch

import (
	"context"
	"strings"
	"testing"
	"time"
)

const (
	edKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmVJ9usp8NnA+maR1qoyQPwSd1NnSdBA32RDLc88st1 yosef@laptop"
	edFP   = "SHA256:LyuXReqhQRG8GybUXZWeRslJ8rx290g7gFlf5jsvatk"
	rsaKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkPqxSpY6zNf2fma7CEcwiwhtXSIWEgFbjjpnIbc/0lIrbLvwTPnLaAcUG6OwSVP6oOCfJ7B1P5JtIdsSIhQQTEO0C+4jiZpM+J7q8Co15FRJ28UVQtMaY4psxm+CUU3p7ZWwj3Fyh+bIRc7MqIdwFOaLEsIB0kgGInETb882JfzqDbUcX3mIjJyyPCeTdDKjDhG03l5yLFICqCxUM8wSN7OnsfiC6BmdTNzP52GA68il9Kpf5FBK4XfAYYtkQl/NsBlA9WXERVkeYXD5O7Wgq2rhEsqSmnzIhqp2geQ2EfVTo2o66trC951pCItVsY+mC9v0Uxde0fz31kxnDYXHD deploy@ci"
	rsaFP  = "SHA256:y4yNAN+/X929zV0z2W8Xdrptp23AvPPWwXWjenVlO6Q"
)

func TestFingerprint(t *testing.T) {
	fp, comment, ok := Fingerprint(edKey)
	if !ok || fp != edFP || comment != "yosef@laptop" {
		t.Errorf("ed25519: %q %q %v", fp, comment, ok)
	}
	fp, _, _ = Fingerprint(`from="1.2.3.4",no-pty ` + rsaKey)
	if fp != rsaFP {
		t.Errorf("rsa with options: %q", fp)
	}
	for _, bad := range []string{"", "# comment", "garbage line here", "ssh-ed25519 !!!notbase64 x"} {
		if _, _, ok := Fingerprint(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
	fps := Fingerprints([]byte(rsaKey + "\n\n# c\n" + edKey + "\n"))
	if len(fps) != 2 || fps[0] != edFP+" yosef@laptop" {
		t.Errorf("Fingerprints = %v", fps)
	}
}

const passwd1 = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
yosef:x:1000:1000::/home/yosef:/bin/bash
`

func keys(m map[string]string) func(string) ([]byte, error) {
	return func(home string) ([]byte, error) { return []byte(m[home]), nil }
}

func TestSnapshotAndDiff(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	old := Snapshot([]byte(passwd1), keys(map[string]string{"/home/yosef": edKey}), []byte("%sudo ALL=(ALL:ALL) ALL\n"), t0)
	if len(old.Users) != 2 || old.Users["yosef"].UID != 1000 {
		t.Errorf("system users must be ignored: %v", old.Users)
	}
	if len(old.Keys["yosef"]) != 1 {
		t.Errorf("keys: %v", old.Keys)
	}
	if evs := Diff(old, old, "", t0); len(evs) != 0 {
		t.Errorf("identical snapshots: %v", evs)
	}

	passwd2 := passwd1 + "deploy:x:1001:1001::/home/deploy:/bin/bash\n_newpkg:x:998:998::/nonexistent:/usr/sbin/nologin\n"
	cur := Snapshot([]byte(passwd2), keys(map[string]string{"/home/yosef": edKey, "/root": rsaKey}), []byte("%sudo ALL=(ALL:ALL) ALL\ndeploy ALL=(ALL) NOPASSWD: ALL\n"), t0.Add(time.Minute))
	evs := Diff(old, cur, SimpleDiff("%sudo ALL=(ALL:ALL) ALL\n", "%sudo ALL=(ALL:ALL) ALL\ndeploy ALL=(ALL) NOPASSWD: ALL\n", 10), t0)
	kinds := map[Kind]Event{}
	for _, e := range evs {
		kinds[e.Kind] = e
	}
	if len(evs) != 3 {
		t.Fatalf("want user_added, key_added, sudoers_changed; got %+v", evs)
	}
	if kinds[UserAdded].User != "deploy" || kinds[UserAdded].Detail != "1001" {
		t.Errorf("user_added: %+v", kinds[UserAdded])
	}
	if kinds[KeyAdded].User != "root" || !strings.HasPrefix(kinds[KeyAdded].Detail, rsaFP) {
		t.Errorf("key_added: %+v", kinds[KeyAdded])
	}
	if kinds[SudoersChanged].Detail != "+ deploy ALL=(ALL) NOPASSWD: ALL" {
		t.Errorf("sudoers diff: %q", kinds[SudoersChanged].Detail)
	}

	// removal direction
	back := Diff(cur, old, "", t0)
	k := map[Kind]bool{}
	for _, e := range back {
		k[e.Kind] = true
	}
	if !k[UserRemoved] || !k[KeyRemoved] || !k[SudoersChanged] {
		t.Errorf("reverse diff: %+v", back)
	}
}

func TestAccountsWatcherRun(t *testing.T) {
	passwd := passwd1
	w := &AccountsWatcher{
		Passwd:   func() ([]byte, error) { return []byte(passwd), nil },
		HomeKeys: keys(nil),
		Sudoers:  func() ([]byte, error) { return []byte("x"), nil },
		Interval: 10 * time.Millisecond,
		StateDir: t.TempDir(),
	}
	st := newState()
	saves := 0
	out := make(chan Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, st, out, func() error { saves++; return nil })

	time.Sleep(50 * time.Millisecond)
	select {
	case e := <-out:
		t.Fatalf("first snapshot must be silent, got %+v", e)
	default:
	}
	if st.Accounts.Taken.IsZero() || saves == 0 {
		t.Fatal("first snapshot must be stored and saved")
	}

	passwd += "guardtest:x:1002:1002::/home/guardtest:/bin/bash\n"
	select {
	case e := <-out:
		if e.Kind != UserAdded || e.User != "guardtest" {
			t.Errorf("got %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event after adding a user")
	}
	if saves < 2 {
		t.Error("state must be saved after a change")
	}
}
