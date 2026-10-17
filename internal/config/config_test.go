package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yosefco3/shedu/internal/i18n"
)

func TestLoadSample(t *testing.T) {
	c, err := Load(filepath.Join("testdata", "guard.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TelegramToken != "123456:ABC-DEF" || c.TelegramChatID != "987654321" {
		t.Errorf("quotes and spaces must be stripped: %+v", c)
	}
	if c.Lang != i18n.En || c.DailyReportAt != "07:30" || c.BruteForceN != 8 {
		t.Errorf("values: %+v", c)
	}
	if c.StateDir != "/var/lib/shedu" || c.Hostname == "" {
		t.Errorf("defaults must survive: %+v", c)
	}
	if !c.TelegramEnabled() {
		t.Error("TelegramEnabled")
	}
}

func TestLoadMissingFile(t *testing.T) {
	c, err := Load("/nonexistent/guard.conf")
	if err != nil || c.BruteForceN != 5 || c.Lang != i18n.He || c.TelegramEnabled() {
		t.Errorf("missing file must give defaults: %+v %v", c, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"TELEGRAM_TOKEN=x\nBOGUS=1\n":  "line 2: unknown key",
		"just words\n":                 "line 1: expected KEY=VALUE",
		"BRUTE_FORCE_THRESHOLD=zero\n": "line 1: BRUTE_FORCE_THRESHOLD",
		"BRUTE_FORCE_THRESHOLD=0\n":    "line 1: BRUTE_FORCE_THRESHOLD",
	}
	for in, want := range cases {
		_, err := Parse(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want containing %q", in, err, want)
		}
	}
}
