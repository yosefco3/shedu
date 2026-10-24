package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yosefco3/shedu/internal/config"
)

const offKey = "shk_abcdefghijkl_fakesecretvalue" // secret-scan: allow

func TestEnrollOffTellsTheCloudFirst(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer srv.Close()
	conf := filepath.Join(t.TempDir(), "guard.conf")
	os.WriteFile(conf, []byte("LANG=en\nCLOUD_URL=\""+srv.URL+"\"\nCLOUD_KEY=\""+offKey+"\"\n"), 0o600) //nolint:errcheck

	if code := run([]string{"enroll", "--off", "--config", conf}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(calls) != 1 || calls[0] != "POST /v1/disconnect Bearer "+offKey {
		t.Fatalf("calls: %q", calls)
	}
	if cfg, _ := config.Load(conf); cfg.CloudEnabled() {
		t.Error("keys must be removed after telling the cloud")
	}
}

func TestEnrollOffWorksWhenTheCloudIsDown(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "guard.conf")
	os.WriteFile(conf, []byte("CLOUD_URL=\"http://127.0.0.1:1\"\nCLOUD_KEY=\""+offKey+"\"\n"), 0o600) //nolint:errcheck
	if code := run([]string{"enroll", "--off", "--config", conf}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(conf)
	if strings.Contains(string(b), "CLOUD_") {
		t.Errorf("must disconnect locally anyway: %s", b)
	}
}
