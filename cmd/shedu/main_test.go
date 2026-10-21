package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"version"}, 0},
		{[]string{"run", "--no-such-flag"}, 2},
		{[]string{"bogus"}, 2},
		{[]string{"check", "--no-such-flag"}, 2},
	}
	for _, c := range cases {
		if got := run(c.args); got != c.want {
			t.Errorf("run(%v) = %d, want %d", c.args, got, c.want)
		}
	}
}

func TestEnrollWritesKeysAndOff(t *testing.T) {
	var got cloudapi.EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)                                                     //nolint:errcheck
		io.WriteString(w, `{"server_id":"abcdefghijkl","key":"shk_abcdefghijkl_fake","url":""}`) //nolint:errcheck // secret-scan: allow
	}))
	defer srv.Close()
	conf := filepath.Join(t.TempDir(), "guard.conf")
	os.WriteFile(conf, []byte("# mine\nLANG=en\nHOSTNAME=web-7\n"), 0o600) //nolint:errcheck

	if code := run([]string{"enroll", "set_fake", "--config", conf, "--url", srv.URL}); code != 0 {
		t.Fatalf("enroll exit %d", code)
	}
	if got.Token != "set_fake" || got.Hostname != "web-7" || got.Arch == "" || got.AgentVersion == "" {
		t.Errorf("request: %+v", got)
	}
	cfg, err := config.Load(conf)
	if err != nil || cfg.CloudKey != "shk_abcdefghijkl_fake" || cfg.CloudURL != srv.URL || cfg.Lang != i18n.En {
		t.Fatalf("config after enroll: %+v %v", cfg, err)
	}
	b, _ := os.ReadFile(conf)
	if !strings.HasPrefix(string(b), "# mine\n") {
		t.Errorf("comment lost: %q", b)
	}
	if code := run([]string{"enroll", "--off", "--config", conf}); code != 0 {
		t.Fatalf("enroll --off exit %d", code)
	}
	if cfg, _ := config.Load(conf); cfg.CloudEnabled() {
		t.Error("--off must remove the key")
	}
	if code := run([]string{"enroll", "--config", conf}); code != 2 {
		t.Errorf("enroll without token: %d", code)
	}
	srv.Close()
	if code := run([]string{"enroll", "set_x", "--config", conf, "--url", srv.URL}); code != 1 {
		t.Errorf("unreachable cloud: %d", code)
	}
}

func TestBuildNotifierRouting(t *testing.T) {
	l := log.New(io.Discard, "", 0)
	tg := config.Config{TelegramToken: "t", TelegramChatID: "c"}
	cl := config.Config{CloudKey: "shk_x_y", CloudURL: "https://api.getshedu.com"}
	both := tg
	both.CloudKey, both.CloudURL = cl.CloudKey, cl.CloudURL
	cases := []struct {
		cfg  config.Config
		want string
		c    bool
	}{
		{config.Config{}, "notify.Stdout", false},
		{tg, "*notify.Telegram", false},
		{cl, "*notify.Cloud", true},
		{both, "*notify.Failover", true},
	}
	for _, c := range cases {
		n, client := buildNotifier(c.cfg, l)
		if got := fmt.Sprintf("%T", n); got != c.want || (client != nil) != c.c {
			t.Errorf("%+v: %s (client %v), want %s", c.cfg, got, client != nil, c.want)
		}
	}
}
