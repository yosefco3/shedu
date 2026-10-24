package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yosefco3/shedu/internal/update"
)

const fixtures = "../../internal/update/testdata/release"

// captureStdout runs f and returns what it printed to stdout.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

// recorder is a test server that logs "METHOD /path" and answers from a handler.
type recorder struct {
	mu    sync.Mutex
	calls []string
	srv   *httptest.Server
}

func newRecorder(t *testing.T, h http.HandlerFunc) *recorder {
	rec := &recorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.calls = append(rec.calls, r.Method+" "+r.URL.Path)
		rec.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func githubLatest(t *testing.T, tag string) *recorder {
	return newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"tag_name":"`+tag+`","draft":false,"prerelease":false}`) //nolint:errcheck
	})
}

func downloads(t *testing.T) *recorder {
	return newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(fixtures, filepath.Base(r.URL.Path)))
	})
}

// seams points the updater at temp paths and test servers; nothing ever runs as root
// or touches /usr/local/bin. It returns the download dir and the "installed" binary.
func seams(t *testing.T, ver string, set func(*update.Updater)) (dir, bin string) {
	t.Helper()
	dir, bin = filepath.Join(t.TempDir(), "update"), filepath.Join(t.TempDir(), "shedu")
	os.WriteFile(bin, []byte("OLD"), 0o755) //nolint:errcheck
	oldVer, oldCfg, oldRoot := version, configureUpdater, isRoot
	version = ver
	configureUpdater = func(u *update.Updater) {
		u.Dir, u.BinPath = dir, bin
		u.Run = func(context.Context, string, ...string) (string, error) {
			t.Error("must not run commands here")
			return "", nil
		}
		set(u)
	}
	isRoot = func() bool { return true }
	t.Cleanup(func() { version, configureUpdater, isRoot = oldVer, oldCfg, oldRoot })
	return dir, bin
}

func content(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// --check on an enrolled server asks GitHub, never the cloud: a heartbeat from the CLI
// would make a server whose daemon is down look alive in the dashboard.
func TestUpgradeCheckChangesNothingAndSendsNoHeartbeat(t *testing.T) {
	cloudSrv := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"latest_version":"v9.9.9"}`) //nolint:errcheck
	})
	gh := githubLatest(t, "v0.3.1")
	dir, bin := seams(t, "v0.3.0", func(u *update.Updater) { u.APIBase = gh.srv.URL })
	conf := filepath.Join(t.TempDir(), "guard.conf")
	os.WriteFile(conf, []byte("CLOUD_URL=\""+cloudSrv.srv.URL+"\"\nCLOUD_KEY=\""+offKey+"\"\n"), 0o600) //nolint:errcheck

	var code int
	out := captureStdout(t, func() { code = run([]string{"upgrade", "--check", "--config", conf}) })
	if code != 0 || !strings.Contains(out, "current v0.3.0, latest v0.3.1\n") || !strings.Contains(out, "an update is available") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if len(cloudSrv.seen()) != 0 {
		t.Errorf("the cloud must not be contacted: %q", cloudSrv.seen())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) || content(t, bin) != "OLD" {
		t.Error("--check must change nothing")
	}
}

func TestUpgradeCheckWithoutCloudAsksGitHub(t *testing.T) {
	gh := githubLatest(t, "v0.3.1")
	seams(t, "v0.3.1", func(u *update.Updater) { u.APIBase = gh.srv.URL })
	var code int
	out := captureStdout(t, func() {
		code = run([]string{"upgrade", "--check", "--config", filepath.Join(t.TempDir(), "none.conf")})
	})
	if code != 0 || !strings.HasPrefix(out, "current v0.3.1, latest v0.3.1\nup to date\n") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
	if got := gh.seen(); len(got) != 1 || got[0] != "GET /repos/yosefco3/shedu/releases/latest" {
		t.Errorf("GitHub calls: %q", got)
	}
}

func TestUpgradeRefusesWithThePlaceholderKey(t *testing.T) {
	gh, dl := githubLatest(t, "v0.3.1"), downloads(t)
	_, bin := seams(t, "v0.3.0", func(u *update.Updater) {
		u.APIBase, u.DownloadBase, u.PublicKey = gh.srv.URL, dl.srv.URL, "REPLACE_WITH_MINISIGN_PUBLIC_KEY"
	})
	var code int
	captureStdout(t, func() { code = run([]string{"upgrade", "--config", "/nonexistent"}) })
	if code != 1 || len(dl.seen()) != 0 || content(t, bin) != "OLD" {
		t.Fatalf("exit %d, downloads %q, binary %q", code, dl.seen(), content(t, bin))
	}
}

// With the real embedded key, a release signed by any other key is refused.
func TestUpgradeRefusesAReleaseNotSignedByTheReleaseKey(t *testing.T) {
	gh, dl := githubLatest(t, "v0.3.1"), downloads(t)
	_, bin := seams(t, "v0.3.0", func(u *update.Updater) { u.APIBase, u.DownloadBase, u.Arch = gh.srv.URL, dl.srv.URL, "amd64" })
	var code int
	captureStdout(t, func() { code = run([]string{"upgrade", "--config", "/nonexistent"}) })
	if code != 1 || content(t, bin) != "OLD" {
		t.Fatalf("exit %d, binary %q", code, content(t, bin))
	}
}

func TestUpgradeInstallsASignedRelease(t *testing.T) {
	key, _ := os.ReadFile(filepath.Join(fixtures, "test.pub"))
	gh, dl := githubLatest(t, "v0.3.1"), downloads(t)
	var ran []string
	_, bin := seams(t, "v0.3.0", func(u *update.Updater) {
		u.PublicKey, u.APIBase, u.DownloadBase, u.Arch = string(key), gh.srv.URL, dl.srv.URL, "amd64"
		u.Run = func(_ context.Context, name string, args ...string) (string, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			switch {
			case strings.HasSuffix(name, ".new"):
				return "v0.3.1\n", nil
			case name == "systemctl":
				return "ActiveState=inactive\nMainPID=0\n", nil
			}
			t.Errorf("unexpected command %s %q", name, args)
			return "", nil
		}
	})
	var code int
	out := captureStdout(t, func() { code = run([]string{"upgrade", "--config", "/nonexistent"}) })
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	want, _ := os.ReadFile(filepath.Join(fixtures, "shedu_linux_amd64"))
	if content(t, bin) != string(want) || content(t, bin+".prev") != "OLD" {
		t.Errorf("binary %q, prev %q", content(t, bin), content(t, bin+".prev"))
	}
	for _, s := range []string{"signature and checksum verified", "not running"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

func TestUpgradeAlreadyUpToDate(t *testing.T) {
	key, _ := os.ReadFile(filepath.Join(fixtures, "test.pub"))
	gh, dl := githubLatest(t, "v0.3.1"), downloads(t)
	_, bin := seams(t, "v0.3.1", func(u *update.Updater) {
		u.PublicKey, u.APIBase, u.DownloadBase = string(key), gh.srv.URL, dl.srv.URL
	})
	var code int
	out := captureStdout(t, func() { code = run([]string{"upgrade", "--config", "/nonexistent"}) })
	if code != 0 || len(dl.seen()) != 0 || content(t, bin) != "OLD" || !strings.Contains(out, "nothing to do") {
		t.Fatalf("exit %d, downloads %q:\n%s", code, dl.seen(), out)
	}
}

func TestUpgradeUsageAndRoot(t *testing.T) {
	if code := run([]string{"upgrade", "--version", "latest"}); code != 2 {
		t.Errorf("bad --version: exit %d", code)
	}
	key, _ := os.ReadFile(filepath.Join(fixtures, "test.pub"))
	dl := downloads(t)
	seams(t, "v0.3.0", func(u *update.Updater) { u.PublicKey, u.DownloadBase = string(key), dl.srv.URL })
	isRoot = func() bool { return false }
	var code int
	captureStdout(t, func() { code = run([]string{"upgrade", "--version", "v0.3.1", "--config", "/nonexistent"}) })
	if code != 1 || len(dl.seen()) != 0 {
		t.Errorf("not root: exit %d, downloads %q", code, dl.seen())
	}
}
