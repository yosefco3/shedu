// Package config loads /etc/shedu/guard.conf: a flat KEY=VALUE file written by
// install.sh. No YAML, no nesting, nothing the owner has to learn.
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/yosefco3/shedu/internal/i18n"
)

// DefaultPath is where install.sh writes the file.
const DefaultPath = "/etc/shedu/guard.conf"

// Config is the complete runtime configuration.
type Config struct {
	TelegramToken  string    // TELEGRAM_TOKEN
	TelegramChatID string    // TELEGRAM_CHAT_ID
	Lang           i18n.Lang // LANG, default he
	DailyReportAt  string    // DAILY_REPORT_AT "HH:MM" local time; "" disables
	BruteForceN    int       // BRUTE_FORCE_THRESHOLD, default 5
	StateDir       string    // STATE_DIR, default /var/lib/shedu
	Hostname       string    // HOSTNAME override; default os.Hostname()
	CloudURL       string    // CLOUD_URL, default https://api.getshedu.com
	CloudKey       string    // CLOUD_KEY, written by `shedu enroll`; empty = cloud off

	Sensitivity Sensitivity // SENSITIVITY low|normal|high, default normal
	Thresholds  Thresholds  // resolved from Sensitivity, then per-key overrides
	Warnings    []string    // non-fatal problems for the daemon to log
}

// Defaults returns the configuration used when the file is absent or a key is missing.
func Defaults() Config {
	host, _ := os.Hostname()
	return Config{Lang: i18n.He, DailyReportAt: "08:00", BruteForceN: 5, StateDir: "/var/lib/shedu", Hostname: host,
		CloudURL:    DefaultCloudURL,
		Sensitivity: Normal, Thresholds: ThresholdsFor(Normal)}
}

// Load reads path; a missing file yields Defaults() with no error.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Defaults(), nil
		}
		return Config{}, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads KEY=VALUE lines. '#' starts a comment, blank lines are ignored,
// values may be wrapped in single or double quotes. Unknown keys are an error
// so that a typo in install.sh never silently disables alerts.
func Parse(r io.Reader) (Config, error) {
	c := Defaults()
	type override struct {
		line     int
		key, val string
	}
	var overrides []override
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("guard.conf line %d: expected KEY=VALUE", n)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		switch key {
		case "TELEGRAM_TOKEN":
			c.TelegramToken = val
		case "TELEGRAM_CHAT_ID":
			c.TelegramChatID = val
		case "LANG":
			c.Lang = i18n.Parse(val)
		case "CLOUD_URL":
			if val != "" {
				c.CloudURL = strings.TrimRight(val, "/")
			}
		case "CLOUD_KEY":
			c.CloudKey = val
		case "DAILY_REPORT_AT":
			c.DailyReportAt = val
		case "BRUTE_FORCE_THRESHOLD":
			i, err := strconv.Atoi(val)
			if err != nil || i < 1 {
				return Config{}, fmt.Errorf("guard.conf line %d: BRUTE_FORCE_THRESHOLD must be a positive number", n)
			}
			c.BruteForceN = i
		case "STATE_DIR":
			c.StateDir = val
		case "HOSTNAME":
			c.Hostname = val
		case "SENSITIVITY":
			s, ok := parseSensitivity(val)
			if !ok {
				c.Warnings = append(c.Warnings, fmt.Sprintf("guard.conf line %d: SENSITIVITY %q is not low, normal or high; using normal", n, val))
			}
			c.Sensitivity = s
		default:
			if isThresholdKey(key) {
				overrides = append(overrides, override{n, key, val})
				continue
			}
			return Config{}, fmt.Errorf("guard.conf line %d: unknown key %q", n, key)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	// The dial sets every threshold; a per-key override always wins, wherever it sits in the file.
	c.Thresholds = ThresholdsFor(c.Sensitivity)
	for _, o := range overrides {
		if err := applyOverride(&c.Thresholds, o.key, o.val); err != nil {
			return Config{}, fmt.Errorf("guard.conf line %d: %v", o.line, err)
		}
	}
	return c, nil
}

// DefaultCloudURL is the Shedu cloud API used when CLOUD_URL is not set.
const DefaultCloudURL = "https://api.getshedu.com"

// CloudEnabled reports whether the agent is enrolled (CLOUD_KEY set). Without it the
// agent never contacts the cloud.
func (c Config) CloudEnabled() bool { return c.CloudKey != "" }

// TelegramEnabled reports whether both Telegram settings are present.
func (c Config) TelegramEnabled() bool { return c.TelegramToken != "" && c.TelegramChatID != "" }
