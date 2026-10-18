package config

import (
	"strings"
	"testing"
	"time"
)

func TestEmptyFileIsNormal(t *testing.T) {
	c, err := Parse(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensitivity != Normal || c.Thresholds != ThresholdsFor(Normal) || len(c.Warnings) != 0 {
		t.Errorf("empty file must give normal thresholds: %+v", c)
	}
	want := Thresholds{MinerCPUPercent: 80, OutboundNewDays: 30, MassFileCount: 200,
		MassFileWindow: 60 * time.Second, OutboundAlerts: OutboundBeacon, ClamAVAt: "03:00"}
	if c.Thresholds != want {
		t.Errorf("normal = %+v, want %+v", c.Thresholds, want)
	}
}

func TestSensitivityDial(t *testing.T) {
	c, err := Parse(strings.NewReader("SENSITIVITY=high\n"))
	if err != nil {
		t.Fatal(err)
	}
	th := c.Thresholds
	if c.Sensitivity != High || th.MinerCPUPercent != 70 || th.OutboundNewDays != 7 ||
		th.MassFileCount != 50 || th.OutboundAlerts != OutboundAll || th.SecretAudit {
		t.Errorf("high: %+v", th)
	}
	c, _ = Parse(strings.NewReader("SENSITIVITY=Low\n"))
	if c.Thresholds.MinerCPUPercent != 90 || c.Thresholds.OutboundNewDays != 90 || c.Thresholds.MassFileCount != 500 {
		t.Errorf("low (case-insensitive): %+v", c.Thresholds)
	}
}

func TestInvalidSensitivityWarns(t *testing.T) {
	c, err := Parse(strings.NewReader("SENSITIVITY=paranoid\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensitivity != Normal || c.Thresholds != ThresholdsFor(Normal) {
		t.Errorf("invalid dial must fall back to normal: %+v", c)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "paranoid") {
		t.Errorf("want one warning naming the value, got %q", c.Warnings)
	}
}

func TestOverrideBeatsDial(t *testing.T) {
	// override written before the dial must still win
	c, err := Parse(strings.NewReader("MINER_CPU_PERCENT=65\nSENSITIVITY=low\nMASSFILE_WINDOW=2m\nCLAMAV_AT=\nSECRET_AUDIT=on\n"))
	if err != nil {
		t.Fatal(err)
	}
	th := c.Thresholds
	if th.MinerCPUPercent != 65 || th.MassFileWindow != 2*time.Minute || th.ClamAVAt != "" || !th.SecretAudit {
		t.Errorf("overrides: %+v", th)
	}
	if th.OutboundNewDays != 90 || th.MassFileCount != 500 {
		t.Errorf("rest must stay low: %+v", th)
	}
	c, _ = Parse(strings.NewReader("MASSFILE_WINDOW=30\nOUTBOUND_ALERTS=OFF\n"))
	if c.Thresholds.MassFileWindow != 30*time.Second || c.Thresholds.OutboundAlerts != OutboundOff {
		t.Errorf("bare seconds / case: %+v", c.Thresholds)
	}
}

func TestOverrideErrors(t *testing.T) {
	cases := map[string]string{
		"MINER_CPU_PERCENT=150\n":     "line 1: MINER_CPU_PERCENT",
		"\nOUTBOUND_NEW_DAYS=soon\n":  "line 2: OUTBOUND_NEW_DAYS",
		"MASSFILE_COUNT=0\n":          "MASSFILE_COUNT",
		"MASSFILE_WINDOW=forever\n":   "MASSFILE_WINDOW",
		"OUTBOUND_ALERTS=loud\n":      "OUTBOUND_ALERTS",
		"SECRET_AUDIT=yes\n":          "SECRET_AUDIT",
		"CLAMAV_AT=3am\n":             "CLAMAV_AT",
		"SENSITIVITY=high\nMINER=1\n": "unknown key",
	}
	for in, want := range cases {
		_, err := Parse(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want containing %q", in, err, want)
		}
	}
}
