package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// TestInstallCloudInContainer runs packaging/install.sh --cloud in a clean ubuntu:24.04
// container against a local fake cloud. Opt-in (needs Docker): SHEDU_DOCKER_TEST=1.
func TestInstallCloudInContainer(t *testing.T) {
	if os.Getenv("SHEDU_DOCKER_TEST") != "1" {
		t.Skip("set SHEDU_DOCKER_TEST=1 to run the install.sh container test")
	}
	var mu sync.Mutex
	var paths []string
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case cloudapi.PathEnroll:
			var req cloudapi.EnrollRequest
			json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
			if req.Token != "set_containertest" {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":"invalid or expired enrollment token"}`) //nolint:errcheck
				return
			}
			io.WriteString(w, `{"server_id":"ctnr00000001","key":"shk_ctnr00000001_fake","url":""}`) //nolint:errcheck // secret-scan: allow
		default:
			io.WriteString(w, `{}`) //nolint:errcheck
		}
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	dir := t.TempDir()
	bin := filepath.Join(dir, "shedu")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	install, _ := filepath.Abs("../../packaging/install.sh")
	run := func(token string) (string, error) {
		cmd := exec.Command("docker", "run", "--rm", "--network", "host",
			"-v", bin+":/shedu:ro", "-v", install+":/install.sh:ro", "ubuntu:24.04",
			"bash", "-c", "bash /install.sh --binary /shedu --yes --cloud "+token+" --url "+srv.URL+
				" && echo ---CONF--- && cat /etc/shedu/guard.conf && stat -c %a /etc/shedu/guard.conf")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run("set_containertest")
	if err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	_, conf, _ := strings.Cut(out, "---CONF---")
	if !strings.Contains(conf, `CLOUD_KEY="shk_ctnr00000001_fake"`) || !strings.Contains(conf, `CLOUD_URL="`+srv.URL+`"`) ||
		strings.Contains(conf, "TELEGRAM_TOKEN") || !strings.HasSuffix(strings.TrimSpace(conf), "600") {
		t.Errorf("guard.conf:\n%s", conf)
	}
	if strings.Contains(out, "BotFather") {
		t.Error("--cloud must not ask about Telegram")
	}
	mu.Lock()
	got := strings.Join(paths, " ")
	mu.Unlock()
	if !strings.Contains(got, "/v1/enroll") || !strings.Contains(got, "/v1/report") {
		t.Errorf("cloud requests: %s (want enroll, then the first check's report)", got)
	}

	out, err = run("set_wrong")
	if err == nil || !strings.Contains(out, "could not connect to the Shedu cloud") || strings.Contains(out, "---CONF---") {
		t.Errorf("a bad token must abort the install:\n%s", out)
	}
}
