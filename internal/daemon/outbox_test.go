package daemon

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// flaky fails the first n sends, like a hotspot that drops for a while.
type flaky struct {
	mu    sync.Mutex
	fails int
	tries int
	got   []string
}

func (f *flaky) Send(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	if f.fails > 0 {
		f.fails--
		return errors.New("context deadline exceeded")
	}
	f.got = append(f.got, s)
	return nil
}

func TestOutboxRetriesInOrder(t *testing.T) {
	n := &flaky{fails: 2}
	var logs strings.Builder
	var lmu sync.Mutex
	o := newOutbox(n, log.New(writerFunc(func(p []byte) (int, error) { lmu.Lock(); defer lmu.Unlock(); return logs.Write(p) }), "", 0),
		5*time.Millisecond, 20*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { o.run(ctx); close(done) }()
	o.put("deleted binary alert")
	o.put("cron alert")
	waitFor(t, func() bool { n.mu.Lock(); defer n.mu.Unlock(); return len(n.got) == 2 })
	cancel()
	<-done
	if n.got[0] != "deleted binary alert" || n.got[1] != "cron alert" || n.tries != 4 {
		t.Errorf("got %v after %d tries", n.got, n.tries)
	}
	lmu.Lock()
	defer lmu.Unlock()
	if !strings.Contains(logs.String(), "retry in") || !strings.Contains(logs.String(), "delivered after retry") {
		t.Errorf("log: %s", logs.String())
	}
}

func TestOutboxStopsOnShutdown(t *testing.T) {
	n := &flaky{fails: 1 << 30}
	o := newOutbox(n, log.New(io.Discard, "", 0), time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { o.run(ctx); close(done) }()
	o.put("x")
	waitFor(t, func() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.tries == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("outbox must stop promptly while waiting to retry")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
