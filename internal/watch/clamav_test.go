package watch

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseClamOutput(t *testing.T) {
	f, _ := os.Open("testdata/clamscan.txt")
	defer f.Close()
	got := ParseClamOutput(f)
	if len(got) != 2 || got[0].Path != "/home/bob/Downloads/invoice.pdf.exe" || got[0].Signature != "Win.Trojan.Agent-123456" ||
		got[1].Path != "/var/www/html/wp-content/uploads/2026/x: y.php" || got[1].Signature != "Php.Webshell.Generic-1" {
		t.Errorf("got %+v", got)
	}
	if n := ParseClamOutput(strings.NewReader("/srv/a: OK\n")); len(n) != 0 {
		t.Errorf("clean: %+v", n)
	}
}

func TestClamWatcher(t *testing.T) {
	out, _ := os.ReadFile("testdata/clamscan.txt")
	var scanned []string
	w := &ClamWatcher{At: "03:00", Targets: []string{"/home", "/var/www"},
		Scan: func(_ context.Context, targets []string) ([]byte, error) { scanned = targets; return out, nil }}
	ev, ok := w.ScanOnce(context.Background())
	if !ok || ev.Kind != ClamDetected || ev.Args["count"] != "2" || strings.Join(scanned, " ") != "/home /var/www" {
		t.Fatalf("event: %+v %v", ev, ok)
	}
	if ev.Args["paths"] != "'/home/bob/Downloads/invoice.pdf.exe' '/var/www/html/wp-content/uploads/2026/x: y.php'" {
		t.Errorf("quoted paths: %s", ev.Args["paths"])
	}
	a, ok := NewRules(5).Feed(ev, newState())
	if !ok || a.ID != "alert.clamav" || !strings.HasPrefix(a.Fix, "sudo mkdir -p /root/quarantine && sudo mv '/home/bob") {
		t.Errorf("alert: %+v", a)
	}

	w.Scan = func(context.Context, []string) ([]byte, error) { return nil, errors.New("boom") }
	if _, ok := w.ScanOnce(context.Background()); ok {
		t.Error("failed scan is not a detection")
	}
}

func TestClamWatcherAbsentIsNoop(t *testing.T) {
	w := &ClamWatcher{At: "03:00", Targets: []string{"/home"}} // no ClamAV
	done := make(chan struct{})
	go func() { w.Run(context.Background(), nil, make(chan Event), nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run must return at once without ClamAV")
	}
	w2 := &ClamWatcher{At: "", Targets: []string{"/home"}, Scan: func(context.Context, []string) ([]byte, error) { return nil, nil }}
	if w2.Available() {
		t.Error("CLAMAV_AT empty disables")
	}
}

func TestNextAt(t *testing.T) {
	now := time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	if n, _ := NextAt(now, "03:00"); !n.Equal(now.AddDate(0, 0, 1)) {
		t.Errorf("same minute rolls to tomorrow: %v", n)
	}
	if n, _ := NextAt(now, "04:30"); !n.Equal(time.Date(2026, 10, 18, 4, 30, 0, 0, time.UTC)) {
		t.Errorf("later today: %v", n)
	}
	if _, err := NextAt(now, "25:00"); err == nil {
		t.Error("bad time")
	}
}
