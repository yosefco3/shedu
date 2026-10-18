package watch

import (
	"strings"
	"testing"

	"github.com/yosefco3/shedu/internal/i18n"
)

// Every phase-2 event kind must become an alert whose text exists in both
// languages and fills every placeholder it uses.
func TestPhase2AlertsRenderInBothLanguages(t *testing.T) {
	args := map[string]string{"pid": "1", "exe": "/tmp/x", "comm": "x", "user": "u", "cmd": "x", "ip": "1.1.1.1", "port": "443",
		"every": "5m0s", "count": "6", "path": "/etc/cron.d/x", "fix": "sudo cat /etc/cron.d/x", "diff": "+ x", "parent": "nginx",
		"dir": "/var/www", "seconds": "60", "sample": "/var/www/a", "cpu": "95", "signal": "pool", "dest": "1.2.3.4:3333",
		"content": "/lib/x.so", "value": "/tmp/x.so", "list": "/home/x (Sig)", "paths": "'/home/x'"}
	events := []Event{
		{Kind: ProcSuspicious, Args: with(args, "reason", ReasonTmpExec)},
		{Kind: ProcSuspicious, Args: with(args, "reason", ReasonDeletedExec)},
		{Kind: OutboundNew, Args: args},
		{Kind: OutboundBeacon, Args: args},
		{Kind: PersistenceNew, Args: args},
		{Kind: ProcLineage, Args: args},
		{Kind: MassFileChange, Args: args},
		{Kind: MinerSuspected, Args: args},
		{Kind: PreloadChanged, Args: with(args, "source", "file")},
		{Kind: PreloadChanged, Args: with(args, "source", "env")},
		{Kind: ClamDetected, Args: args},
	}
	for _, ev := range events {
		a, ok := NewRules(5).Feed(ev, newState())
		if !ok {
			t.Errorf("%s: no alert", ev.Kind)
			continue
		}
		for _, lang := range []i18n.Lang{i18n.En, i18n.He} {
			if _, ok := i18n.Get(lang, a.ID); !ok {
				t.Errorf("%s: %s missing in %s", ev.Kind, a.ID, lang)
			}
			text := a.Telegram(lang)
			if strings.Contains(text, "<no value>") || strings.Contains(text, "{{") {
				t.Errorf("%s/%s: unfilled text %q", a.ID, lang, text)
			}
		}
		if a.Fix == "" {
			t.Errorf("%s: every alert needs a command", a.ID)
		}
	}
}

func with(m map[string]string, k, v string) map[string]string {
	out := map[string]string{k: v}
	for kk, vv := range m {
		if kk != k {
			out[kk] = vv
		}
	}
	return out
}
