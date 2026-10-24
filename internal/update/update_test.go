package update

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------------------

func pubKeyString(t *testing.T) string { return string(readFile(t, "test.pub")) }

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// stageRelease copies SHA256SUMS, the named signature and the amd64 fixture binary (under
// binName) into a fresh temp dir and returns their paths.
func stageRelease(t *testing.T, sigName, binName string) (sums, sig, bin string) {
	t.Helper()
	dir := t.TempDir()
	put := func(src, dst string) string {
		p := filepath.Join(dir, dst)
		if err := os.WriteFile(p, readFile(t, src), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return put("SHA256SUMS", "SHA256SUMS"), put(sigName, "SHA256SUMS.minisig"), put("shedu_linux_amd64", binName)
}

// fixtureServer serves testdata/release under /v0.3.1/, counting requests. Names in
// missing answer 404.
type fixtureServer struct {
	*httptest.Server
	hits int32
}

func newFixtureServer(t *testing.T, missing ...string) *fixtureServer {
	t.Helper()
	fs := &fixtureServer{}
	gone := map[string]bool{}
	for _, m := range missing {
		gone[m] = true
	}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fs.hits, 1)
		name, ok := strings.CutPrefix(r.URL.Path, "/v0.3.1/")
		if !ok || gone[name] {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile("testdata/release/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *fixtureServer) requests() int { return int(atomic.LoadInt32(&fs.hits)) }

// fakeHost stands in for systemctl, systemd-run and the new binary's "version" command.
type fakeHost struct {
	bin         string
	versionOut  string
	stateBefore string
	stateAfter  string
	pidAfter    func(poll int) int
	calls       []string
	scheduled   bool
	polls       int
	restored    bool // a plain `systemctl restart` (the rollback) happened
	staysDown   bool // the service does not come back even after the rollback
}

func (h *fakeHost) run(_ context.Context, name string, args ...string) (string, error) {
	h.calls = append(h.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	switch {
	case name == h.bin+".new":
		return h.versionOut + "\n", nil
	case name == "systemd-run":
		h.scheduled = true
	case name == "systemctl" && len(args) > 0 && args[0] == "restart":
		h.restored = true
	case name == "systemctl" && len(args) > 0 && args[0] == "show":
		if h.restored && !h.staysDown {
			return "ActiveState=active\nMainPID=300\n", nil
		}
		if !h.scheduled {
			return "ActiveState=" + h.stateBefore + "\nMainPID=100\n", nil
		}
		h.polls++
		return fmt.Sprintf("ActiveState=%s\nMainPID=%d\n", h.stateAfter, h.pidAfter(h.polls)), nil
	}
	return "", nil
}

// index returns the position of the first call with this prefix, or -1.
func (h *fakeHost) index(prefix string) int {
	for i, c := range h.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// newApplyUpdater builds an Updater wired to a fakeHost, with BinPath holding "OLD", and
// returns a temp copy of the fixture binary (Apply removes its source).
func newApplyUpdater(t *testing.T) (*Updater, *fakeHost, string) {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "shedu")
	if err := os.WriteFile(binPath, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, src := stageRelease(t, "SHA256SUMS.minisig", "shedu_linux_amd64") // Apply verifies again
	h := &fakeHost{bin: binPath, versionOut: "v0.3.1", stateBefore: "active", stateAfter: "active",
		pidAfter: func(int) int { return 200 }}
	u := &Updater{PublicKey: pubKeyString(t), BinPath: binPath, Run: h.run,
		Sleep: func(time.Duration) {}, UpWithin: 30 * time.Second}
	return u, h, src
}

// --- Verify ------------------------------------------------------------------------------

func TestVerifyAcceptsSignedRelease(t *testing.T) {
	for _, sigName := range []string{"SHA256SUMS.minisig", "SHA256SUMS.legacy.minisig"} {
		t.Run(sigName, func(t *testing.T) {
			sums, sig, bin := stageRelease(t, sigName, "shedu_linux_amd64")
			if err := (&Updater{PublicKey: pubKeyString(t)}).Verify(sums, sig, bin, "v0.3.1"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A build carrying the placeholder (a fork without its own key) can never update itself.
func TestPlaceholderBuildNeverUpdates(t *testing.T) {
	sums, sig, bin := stageRelease(t, "SHA256SUMS.minisig", "shedu_linux_amd64")
	for name, u := range map[string]*Updater{
		"explicit placeholder key": {PublicKey: placeholderKey},
		"blank key":                {PublicKey: "   "},
	} {
		if err := u.Verify(sums, sig, bin, "v0.3.1"); !errors.Is(err, ErrNoReleaseKey) {
			t.Errorf("%s: got %v, want ErrNoReleaseKey", name, err)
		}
	}
}

func TestVerifyRefusesBadReleases(t *testing.T) {
	good := "SHA256SUMS.minisig"
	tests := []struct {
		name    string
		sigName string
		binName string
		tamper  bool   // append a byte to the binary
		noSig   bool   // point at a signature file that does not exist
		version string // default v0.3.1
		wantIs  error
		wantMsg string
	}{
		{name: "binary changed", sigName: good, binName: "shedu_linux_amd64", tamper: true, wantMsg: "checksum mismatch"},
		{name: "signed by another key", sigName: "SHA256SUMS.otherkey.minisig", binName: "shedu_linux_amd64",
			wantIs: ErrSignatureInvalid, wantMsg: "signature invalid"},
		{name: "signature missing, no sha-only fallback", sigName: good, binName: "shedu_linux_amd64", noSig: true,
			wantMsg: "refusing to update"},
		{name: "old signed release passed off as a newer one", sigName: good, binName: "shedu_linux_amd64",
			version: "v0.3.2", wantIs: ErrSignatureInvalid},
		{name: "binary not listed in SHA256SUMS", sigName: good, binName: "shedu_linux_riscv", wantMsg: "does not list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sums, sig, bin := stageRelease(t, tc.sigName, tc.binName)
			if tc.tamper {
				f, err := os.OpenFile(bin, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.Write([]byte{'x'})
				f.Close()
			}
			if tc.noSig {
				sig = filepath.Join(filepath.Dir(sig), "does-not-exist.minisig")
			}
			v := tc.version
			if v == "" {
				v = "v0.3.1"
			}
			err := (&Updater{PublicKey: pubKeyString(t)}).Verify(sums, sig, bin, v)
			if err == nil {
				t.Fatal("Verify accepted it")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("got %v, want errors.Is %v", err, tc.wantIs)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("got %q, want it to contain %q", err, tc.wantMsg)
			}
		})
	}
}

// --- Fetch -------------------------------------------------------------------------------

func TestFetchDownloadsThreeFilesThatVerify(t *testing.T) {
	srv := newFixtureServer(t)
	u := &Updater{PublicKey: pubKeyString(t), DownloadBase: srv.URL, Dir: t.TempDir()}
	bin, err := u.Fetch(context.Background(), "v0.3.1", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(u.Dir, "shedu_linux_amd64"); bin != want {
		t.Fatalf("binary path %q, want %q", bin, want)
	}
	for _, name := range []string{"shedu_linux_amd64", "SHA256SUMS", "SHA256SUMS.minisig"} {
		if mustRead(t, filepath.Join(u.Dir, name)) != string(readFile(t, name)) {
			t.Errorf("%s was not downloaded intact", name)
		}
	}
	if err := u.Verify(filepath.Join(u.Dir, "SHA256SUMS"), filepath.Join(u.Dir, "SHA256SUMS.minisig"), bin, "v0.3.1"); err != nil {
		t.Fatalf("fetched files do not verify: %v", err)
	}
}

func TestFetchRefusesBadInputWithoutAnyRequest(t *testing.T) {
	tests := []struct{ name, version, arch string }{
		{"latest is not a version", "latest", "amd64"},
		{"pre-release", "v0.3.1-rc1", "amd64"},
		{"path traversal", "../x", "amd64"},
		{"two-part version", "v0.3", "amd64"},
		{"unsupported architecture", "v0.3.1", "386"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFixtureServer(t)
			u := &Updater{DownloadBase: srv.URL, Dir: t.TempDir()}
			if _, err := u.Fetch(context.Background(), tc.version, tc.arch); err == nil {
				t.Fatal("Fetch accepted it")
			}
			if n := srv.requests(); n != 0 {
				t.Errorf("server got %d requests, want 0", n)
			}
		})
	}
}

func TestFetchUnsignedReleaseIsRefusedAndStaleSignatureRemoved(t *testing.T) {
	srv := newFixtureServer(t, "SHA256SUMS.minisig")
	dir := t.TempDir()
	stale := filepath.Join(dir, "SHA256SUMS.minisig")
	if err := os.WriteFile(stale, readFile(t, "SHA256SUMS.minisig"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &Updater{DownloadBase: srv.URL, Dir: dir}
	_, err := u.Fetch(context.Background(), "v0.3.1", "amd64")
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("got %v, want a \"not signed\" error", err)
	}
	if exists(stale) {
		t.Error("the stale SHA256SUMS.minisig from an earlier run is still there")
	}
}

// --- Latest ------------------------------------------------------------------------------

func TestLatest(t *testing.T) {
	const release = `{"tag_name":"v0.3.2","draft":false,"prerelease":false}`
	cloud := func(v string, err error) func(context.Context) (string, error) {
		return func(context.Context) (string, error) { return v, err }
	}
	tests := []struct {
		name     string
		cloud    func(context.Context) (string, error)
		status   int
		body     string
		want     string
		wantErr  bool
		wantHits int
	}{
		{name: "cloud answer is used, GitHub not asked", cloud: cloud("v0.3.1", nil), status: 200, body: release, want: "v0.3.1"},
		{name: "cloud error falls back to GitHub", cloud: cloud("", errors.New("offline")), status: 200, body: release, want: "v0.3.2", wantHits: 1},
		{name: "cloud garbage falls back to GitHub", cloud: cloud("garbage", nil), status: 200, body: release, want: "v0.3.2", wantHits: 1},
		{name: "not enrolled", status: 200, body: release, want: "v0.3.2", wantHits: 1},
		{name: "pre-release is refused", status: 200, body: `{"tag_name":"v0.3.2","prerelease":true}`, wantErr: true, wantHits: 1},
		{name: "draft is refused", status: 200, body: `{"tag_name":"v0.3.2","draft":true}`, wantErr: true, wantHits: 1},
		{name: "odd tag is refused", status: 200, body: `{"tag_name":"v0.3.2-rc1"}`, wantErr: true, wantHits: 1},
		{name: "HTTP 500", status: 500, body: "boom", wantErr: true, wantHits: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				if r.URL.Path != "/repos/yosefco3/shedu/releases/latest" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				if r.Header.Get("User-Agent") == "" {
					t.Error("request has no User-Agent")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			u := &Updater{APIBase: srv.URL, Cloud: tc.cloud}
			got, err := u.Latest(context.Background())
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("got (%q, %v), want (%q, error=%v)", got, err, tc.want, tc.wantErr)
			}
			if n := int(atomic.LoadInt32(&hits)); n != tc.wantHits {
				t.Errorf("GitHub got %d requests, want %d", n, tc.wantHits)
			}
		})
	}
}

// --- Apply -------------------------------------------------------------------------------

const restartCall = "systemd-run --on-active=2 --quiet systemctl restart shedu"

func TestApplyInstallsAndRestarts(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	res, err := u.Apply(context.Background(), src, "v0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Restarted || res.NotRunning {
		t.Errorf("result %+v, want Restarted", res)
	}
	if got := mustRead(t, u.BinPath); got != string(readFile(t, "shedu_linux_amd64")) {
		t.Errorf("BinPath holds %q, not the new binary", got)
	}
	if got := mustRead(t, u.BinPath+".prev"); got != "OLD" {
		t.Errorf(".prev holds %q, want OLD", got)
	}
	if fi, err := os.Stat(u.BinPath); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("BinPath mode %v (%v), want 0755", fi.Mode().Perm(), err)
	}
	if exists(src) {
		t.Error("the source binary was not removed")
	}
	if exists(u.BinPath + ".new") {
		t.Error("BinPath.new was left behind")
	}
	if h.index(restartCall) < 0 {
		t.Errorf("restart was not scheduled; calls: %q", h.calls)
	}
}

func TestApplyRollsBackWhenServiceDoesNotComeUp(t *testing.T) {
	tests := []struct {
		name  string
		state string
		pid   func(poll int) int
	}{
		{"main PID never changes", "active", func(int) int { return 100 }},
		{"service failed after restart", "failed", func(int) int { return 200 }},
		{"crash loop: new PID on every poll", "active", func(poll int) int { return 200 + poll }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, h, src := newApplyUpdater(t)
			h.stateAfter, h.pidAfter = tc.state, tc.pid
			_, err := u.Apply(context.Background(), src, "v0.3.1")
			if !errors.Is(err, ErrRolledBack) {
				t.Fatalf("got %v, want ErrRolledBack", err)
			}
			if got := mustRead(t, u.BinPath); got != "OLD" {
				t.Errorf("BinPath holds %q after rollback, want OLD", got)
			}
			sched, restart := h.index("systemd-run"), h.index("systemctl restart shedu")
			if restart < 0 || restart < sched {
				t.Errorf("no plain restart after the rollback; calls: %q", h.calls)
			}
		})
	}
}

func TestApplyNeedsAStableNewProcess(t *testing.T) {
	// The new PID must hold for several polls, not just appear once.
	u, h, src := newApplyUpdater(t)
	h.pidAfter = func(poll int) int {
		if poll < 3 {
			return 100 // still the old process for two polls
		}
		return 200
	}
	if res, err := u.Apply(context.Background(), src, "v0.3.1"); err != nil || !res.Restarted {
		t.Fatalf("got (%+v, %v), want a restart", res, err)
	}
	if h.polls < 7 {
		t.Errorf("only %d polls: success was declared before the new PID was stable", h.polls)
	}
}

func TestApplyRefusesBinaryWithWrongVersion(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	h.versionOut = "v0.3.0"
	if _, err := u.Apply(context.Background(), src, "v0.3.1"); err == nil {
		t.Fatal("Apply installed a binary that reports the wrong version")
	}
	if got := mustRead(t, u.BinPath); got != "OLD" {
		t.Errorf("BinPath holds %q, want OLD", got)
	}
	if exists(u.BinPath + ".new") {
		t.Error("BinPath.new was left behind")
	}
	if h.index("systemd-run") >= 0 {
		t.Error("the service was restarted anyway")
	}
}

func TestApplyDoesNotRestartAStoppedService(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	h.stateBefore = "inactive"
	res, err := u.Apply(context.Background(), src, "v0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotRunning || res.Restarted {
		t.Errorf("result %+v, want NotRunning", res)
	}
	if got := mustRead(t, u.BinPath); got != string(readFile(t, "shedu_linux_amd64")) {
		t.Errorf("BinPath holds %q, not the new binary", got)
	}
	if h.index("systemd-run") >= 0 {
		t.Error("a stopped service was restarted")
	}
}

// --- Upgrade -----------------------------------------------------------------------------

func TestUpgradeEndToEnd(t *testing.T) {
	srv := newFixtureServer(t)
	u, h, _ := newApplyUpdater(t)
	u.DownloadBase, u.Dir, u.Arch = srv.URL, t.TempDir(), "amd64"
	res, err := u.Upgrade(context.Background(), "v0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Restarted {
		t.Errorf("result %+v, want Restarted", res)
	}
	if got := mustRead(t, u.BinPath); got != string(readFile(t, "shedu_linux_amd64")) {
		t.Errorf("BinPath holds %q, not the new binary", got)
	}
	if h.index(restartCall) < 0 {
		t.Errorf("restart was not scheduled; calls: %q", h.calls)
	}
}

func TestUpgradeWithPlaceholderKeyTouchesNothing(t *testing.T) {
	srv := newFixtureServer(t)
	u, h, _ := newApplyUpdater(t)
	u.PublicKey = placeholderKey
	u.DownloadBase, u.Dir, u.Arch = srv.URL, t.TempDir(), "amd64"
	_, err := u.Upgrade(context.Background(), "v0.3.1")
	if !errors.Is(err, ErrNoReleaseKey) {
		t.Fatalf("got %v, want ErrNoReleaseKey", err)
	}
	if got := mustRead(t, u.BinPath); got != "OLD" {
		t.Errorf("BinPath holds %q, want OLD", got)
	}
	if len(h.calls) != 0 {
		t.Errorf("commands were run: %q", h.calls)
	}
	if exists(filepath.Join(u.Dir, "shedu_linux_amd64")) {
		t.Error("the unverified download was left in Dir")
	}
}

func TestApplyReportsWhenTheRollbackDoesNotComeUpEither(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	h.stateAfter, h.staysDown = "failed", true
	_, err := u.Apply(context.Background(), src, "v0.3.1")
	if !errors.Is(err, ErrRollbackDown) {
		t.Fatalf("got %v, want ErrRollbackDown", err)
	}
	if mustRead(t, u.BinPath) != "OLD" {
		t.Error("the previous binary must be back even so")
	}
}

func TestApplyVerifiesTheStagedBytesAgain(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho swapped after Verify\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := u.Apply(context.Background(), src, "v0.3.1")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v, want a checksum mismatch", err)
	}
	if mustRead(t, u.BinPath) != "OLD" || exists(u.BinPath+".new") || len(h.calls) != 0 {
		t.Errorf("nothing may run or change: calls %q", h.calls)
	}
}

func TestApplyNeedsAnInstalledBinary(t *testing.T) {
	u, h, src := newApplyUpdater(t)
	os.Remove(u.BinPath) //nolint:errcheck
	if _, err := u.Apply(context.Background(), src, "v0.3.1"); err == nil || !strings.Contains(err.Error(), "install.sh") {
		t.Fatalf("got %v", err)
	}
	if exists(u.BinPath) || len(h.calls) != 0 {
		t.Error("nothing may be installed or run")
	}
}

func TestRedirectToPlainHTTPIsRefused(t *testing.T) {
	from, _ := http.NewRequest("GET", "https://github.com/x", nil)
	to, _ := http.NewRequest("GET", "http://objects.example/x", nil)
	if httpsOnlyRedirects(to, []*http.Request{from}) == nil {
		t.Error("https to http must be refused")
	}
	to2, _ := http.NewRequest("GET", "https://objects.example/x", nil)
	if err := httpsOnlyRedirects(to2, []*http.Request{from}); err != nil {
		t.Errorf("https to https: %v", err)
	}
}

func TestOnlyOneUpgradeAtATime(t *testing.T) {
	u := &Updater{Dir: t.TempDir()}
	unlock, err := u.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Lock(); err == nil {
		t.Error("a second lock must fail while the first is held")
	}
	unlock()
	unlock2, err := u.Lock()
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	unlock2()
}

func TestFetchRefusesAnOversizedBinary(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "shedu_linux_amd64") {
			w.Write(make([]byte, maxBinary+1)) //nolint:errcheck
			return
		}
		w.Write([]byte("small")) //nolint:errcheck
	}))
	defer big.Close()
	u := &Updater{DownloadBase: big.URL, Dir: t.TempDir()}
	if _, err := u.Fetch(context.Background(), "v0.3.1", "amd64"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("got %v", err)
	}
	if exists(filepath.Join(u.Dir, "shedu_linux_amd64")) {
		t.Error("the partial download must be removed")
	}
}

// The embedded key is the real release key, and it does not accept the test key's signatures.
func TestEmbeddedReleaseKey(t *testing.T) {
	pk, err := ParsePublicKey(ReleasePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%X", []byte{pk.ID[7], pk.ID[6], pk.ID[5], pk.ID[4], pk.ID[3], pk.ID[2], pk.ID[1], pk.ID[0]}); got != "9D437473DF0283EF" {
		t.Errorf("key id %s", got)
	}
	sums, sig, bin := stageRelease(t, "SHA256SUMS.minisig", "shedu_linux_amd64")
	if err := (&Updater{}).Verify(sums, sig, bin, "v0.3.1"); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a release signed by the test key: got %v, want ErrSignatureInvalid", err)
	}
}

// The same release key must appear in every place users and the release workflow read it.
func TestReleaseKeyIsTheSameEverywhere(t *testing.T) {
	install := mustRead(t, "../../packaging/install.sh")
	if !strings.Contains(install, "\nMINISIGN_PUBKEY=\""+ReleasePublicKey+"\"\n") {
		t.Error("packaging/install.sh: MINISIGN_PUBKEY differs from ReleasePublicKey")
	}
	for _, f := range []string{"../../README.md", "../../SECURITY.md"} {
		if !strings.Contains(mustRead(t, f), ReleasePublicKey) {
			t.Errorf("%s does not show ReleasePublicKey", f)
		}
	}
}
