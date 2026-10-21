package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yosefco3/shedu/internal/cloud"
	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/watch"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

type fakeCloudServer struct {
	mu     sync.Mutex
	paths  []string
	events []cloudapi.Event
	hbs    []cloudapi.Heartbeat
	rep    []cloudapi.Report
}

func (f *fakeCloudServer) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)
	switch r.URL.Path {
	case cloudapi.PathEvents:
		var evs []cloudapi.Event
		json.Unmarshal(b, &evs) //nolint:errcheck
		f.events = append(f.events, evs...)
		io.WriteString(w, `{"accepted":1}`) //nolint:errcheck
	case cloudapi.PathHeartbeat:
		var hb cloudapi.Heartbeat
		json.Unmarshal(b, &hb) //nolint:errcheck
		f.hbs = append(f.hbs, hb)
		io.WriteString(w, `{"latest_version":"v9.9.9"}`) //nolint:errcheck
	case cloudapi.PathReport:
		var rep cloudapi.Report
		json.Unmarshal(b, &rep) //nolint:errcheck
		f.rep = append(f.rep, rep)
	}
}

func (f *fakeCloudServer) counts() (ev, hb, rep int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.events), len(f.hbs), len(f.rep)
}

func TestDaemonCloud(t *testing.T) {
	fc := &fakeCloudServer{}
	srv := httptest.NewServer(http.HandlerFunc(fc.handler))
	defer srv.Close()
	var logMu sync.Mutex
	var logs strings.Builder
	logger := log.New(writerFunc(func(p []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logs.Write(p) }), "", 0)
	client := &cloud.Client{BaseURL: srv.URL, Key: "shk_testserver01_fake", Version: "v0.3.0", Logf: logger.Printf} // secret-scan: allow
	src := &fakeSource{ch: make(chan watch.Event)}
	d := &Daemon{
		Cfg:            config.Config{Lang: i18n.He, Hostname: "web-1", TelegramToken: "t", TelegramChatID: "c"},
		Notifier:       &notify.Cloud{Client: client},
		Auth:           src,
		Rules:          watch.NewRules(5),
		State:          &watch.State{KnownIPs: map[string]time.Time{"9.9.9.9": time.Now()}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		RunCheck:       func(context.Context) finding.Report { return finding.Report{Host: "x", Time: time.Now()} },
		Log:            logger,
		Version:        "v0.3.0",
		Cloud:          client,
		HeartbeatEvery: 20 * time.Millisecond,
		Addrs:          func() []string { return []string{"10.0.0.5"} },
		Uptime:         func() int64 { return 42 },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Run(ctx) }()

	waitFor(t, func() bool { _, hb, rep := fc.counts(); return hb >= 2 && rep == 1 })
	for i := 0; i < 5; i++ {
		src.ch <- watch.Event{Kind: watch.LoginFail, IP: "1.2.3.4", User: "root"}
	}
	waitFor(t, func() bool { ev, _, _ := fc.counts(); return ev == 1 })
	cancel()
	<-done

	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.rep[0].Host != "web-1" || fc.rep[0].AgentVersion != "v0.3.0" {
		t.Errorf("start-up report: %+v", fc.rep[0])
	}
	if e := fc.events[0]; e.UID == "" || e.ID != "alert.bruteforce" || e.Text["he"].Title == "" {
		t.Errorf("event: %+v", e)
	}
	hb := fc.hbs[0]
	if hb.AgentVersion != "v0.3.0" || !hb.DirectTelegram || hb.UptimeSeconds != 42 || hb.Lang != "he" ||
		len(hb.Addrs) != 1 || strings.Join(hb.Watchers, ",") != "auth" {
		t.Errorf("heartbeat: %+v", hb)
	}
	if d.latestVersion() != "v9.9.9" {
		t.Errorf("latest version not recorded: %q", d.latestVersion())
	}
	logMu.Lock()
	out := logs.String()
	logMu.Unlock()
	if !strings.Contains(out, "cloud: POST /v1/report 200") || !strings.Contains(out, "cloud: POST /v1/events 200") ||
		!strings.Contains(out, "a newer shedu is available: v9.9.9") || strings.Contains(out, "shk_") {
		t.Errorf("log:\n%s", out)
	}
}

func TestDaemonWithoutCloudSendsNothing(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	d := &Daemon{
		Cfg:      config.Config{Lang: i18n.En, Hostname: "h"},
		Notifier: &recorder{},
		Rules:    watch.NewRules(5),
		State:    &watch.State{KnownIPs: map[string]time.Time{"1.1.1.1": time.Now()}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		RunCheck: func(context.Context) finding.Report {
			t.Error("no start-up check without cloud")
			return finding.Report{}
		},
		Log: log.New(io.Discard, "", 0),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	d.Run(ctx) //nolint:errcheck
	if hits != 0 {
		t.Errorf("%d requests without a cloud key", hits)
	}
}

func TestDailyReportMentionsNewVersion(t *testing.T) {
	rec := &recorder{}
	d := &Daemon{Cfg: config.Config{Lang: i18n.En, Hostname: "h"}, Version: "v0.3.0", Log: log.New(io.Discard, "", 0),
		RunCheck: func(context.Context) finding.Report { return finding.Report{Host: "h"} }}
	d.out = newOutbox(rec, d.Log, time.Millisecond, time.Millisecond)
	d.noteLatest("v0.3.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.out.run(ctx)
	d.sendDaily(ctx)
	waitFor(t, func() bool { return rec.count() == 1 })
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !strings.Contains(rec.msgs[0], "v0.3.1") || rec.full[0].Report == nil {
		t.Errorf("daily: %q", rec.msgs[0])
	}
}
