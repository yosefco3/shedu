package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sensitivity is the one dial the owner turns: how noisy Shedu is, not what
// is safe. The security lists themselves (suspicious exec dirs, pool ports,
// web servers) stay in code and are not configurable.
type Sensitivity string

const (
	Low    Sensitivity = "low"
	Normal Sensitivity = "normal"
	High   Sensitivity = "high"
)

// Outbound alert modes for OUTBOUND_ALERTS.
const (
	OutboundOff    = "off"
	OutboundBeacon = "beacon"
	OutboundAll    = "all"
)

// Thresholds are the resolved phase-2 tuning values. Watchers read these and
// never parse raw guard.conf keys themselves.
type Thresholds struct {
	MinerCPUPercent int           // MINER_CPU_PERCENT
	OutboundNewDays int           // OUTBOUND_NEW_DAYS: unseen this long = "new destination"
	MassFileCount   int           // MASSFILE_COUNT changed files ...
	MassFileWindow  time.Duration // MASSFILE_WINDOW ... within this window
	OutboundAlerts  string        // OUTBOUND_ALERTS: off|beacon|all
	SecretAudit     bool          // SECRET_AUDIT: opt-in, needs auditd (phase 3)
	ClamAVAt        string        // CLAMAV_AT "HH:MM"; "" disables
}

// ThresholdsFor returns the defaults for a dial position; anything unknown is Normal.
func ThresholdsFor(s Sensitivity) Thresholds {
	t := Thresholds{
		MinerCPUPercent: 80,
		OutboundNewDays: 30,
		MassFileCount:   200,
		MassFileWindow:  60 * time.Second,
		OutboundAlerts:  OutboundBeacon,
		ClamAVAt:        "03:00",
	}
	switch s {
	case Low:
		t.MinerCPUPercent, t.OutboundNewDays, t.MassFileCount = 90, 90, 500
	case High:
		t.MinerCPUPercent, t.OutboundNewDays, t.MassFileCount = 70, 7, 50
		t.OutboundAlerts = OutboundAll
	}
	return t
}

// parseSensitivity reports ok=false for anything but low|normal|high.
func parseSensitivity(v string) (Sensitivity, bool) {
	switch s := Sensitivity(strings.ToLower(v)); s {
	case Low, Normal, High:
		return s, true
	}
	return Normal, false
}

// isThresholdKey reports whether key is a per-threshold override.
func isThresholdKey(key string) bool {
	switch key {
	case "MINER_CPU_PERCENT", "OUTBOUND_NEW_DAYS", "MASSFILE_COUNT", "MASSFILE_WINDOW",
		"OUTBOUND_ALERTS", "SECRET_AUDIT", "CLAMAV_AT":
		return true
	}
	return false
}

// applyOverride sets one expert override on t. Bad values are an error, like
// BRUTE_FORCE_THRESHOLD: a typo must never silently change what is watched.
func applyOverride(t *Thresholds, key, val string) error {
	positive := func(max int) (int, error) {
		i, err := strconv.Atoi(val)
		if err != nil || i < 1 || i > max {
			return 0, fmt.Errorf("%s must be a number from 1 to %d", key, max)
		}
		return i, nil
	}
	var err error
	switch key {
	case "MINER_CPU_PERCENT":
		t.MinerCPUPercent, err = positive(100)
	case "OUTBOUND_NEW_DAYS":
		t.OutboundNewDays, err = positive(3650)
	case "MASSFILE_COUNT":
		t.MassFileCount, err = positive(1_000_000)
	case "MASSFILE_WINDOW":
		// "60s", "2m", or a bare number of seconds
		d, perr := time.ParseDuration(val)
		if perr != nil {
			if i, aerr := strconv.Atoi(val); aerr == nil {
				d, perr = time.Duration(i)*time.Second, nil
			}
		}
		if perr != nil || d < time.Second {
			return fmt.Errorf("MASSFILE_WINDOW must be a duration like 60s or 2m")
		}
		t.MassFileWindow = d
	case "OUTBOUND_ALERTS":
		switch v := strings.ToLower(val); v {
		case OutboundOff, OutboundBeacon, OutboundAll:
			t.OutboundAlerts = v
		default:
			return fmt.Errorf("OUTBOUND_ALERTS must be off, beacon or all")
		}
	case "SECRET_AUDIT":
		switch strings.ToLower(val) {
		case "on":
			t.SecretAudit = true
		case "off":
			t.SecretAudit = false
		default:
			return fmt.Errorf("SECRET_AUDIT must be on or off")
		}
	case "CLAMAV_AT":
		if val != "" {
			if _, perr := time.Parse("15:04", val); perr != nil {
				return fmt.Errorf("CLAMAV_AT must be HH:MM, or empty to disable")
			}
		}
		t.ClamAVAt = val
	}
	return err
}
