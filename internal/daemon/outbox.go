package daemon

import (
	"context"
	"log"
	"time"

	"github.com/yosefco3/shedu/internal/notify"
)

// outbox delivers messages in order and keeps retrying the ones that failed:
// a server on a flaky link (a phone hotspot, a short outage) must not lose an
// alert. Sending runs in its own goroutine so a slow network never stalls
// the event loop. Messages live in memory only.
type outbox struct {
	n        notify.Notifier
	log      *log.Logger
	q        chan string
	min, max time.Duration // retry backoff bounds
}

// outboxCap bounds memory during a long outage; the oldest are dropped first.
const outboxCap = 200

func newOutbox(n notify.Notifier, l *log.Logger, min, max time.Duration) *outbox {
	if min <= 0 {
		min = 10 * time.Second
	}
	if max < min {
		max = 5 * time.Minute
	}
	return &outbox{n: n, log: l, q: make(chan string, outboxCap), min: min, max: max}
}

// put queues a message without blocking.
func (o *outbox) put(text string) {
	select {
	case o.q <- text:
	default:
		o.log.Printf("notify: outbox full, message dropped")
	}
}

// run sends until ctx ends.
func (o *outbox) run(ctx context.Context) {
	var pending []string
	add := func(m string) {
		pending = append(pending, m)
		if len(pending) > outboxCap {
			pending = pending[1:]
			o.log.Printf("notify: outbox full, oldest message dropped")
		}
	}
	backoff := o.min
	failed := false
	for {
		if len(pending) == 0 {
			select {
			case m := <-o.q:
				add(m)
			case <-ctx.Done():
				return
			}
		}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := o.n.Send(sctx, pending[0])
		cancel()
		if err == nil {
			pending = pending[1:]
			if failed {
				o.log.Printf("notify: delivered after retry")
			}
			backoff, failed = o.min, false
			continue
		}
		if ctx.Err() != nil {
			o.log.Printf("notify: stopping with %d unsent message(s)", len(pending))
			return
		}
		o.log.Printf("notify: %v (%d waiting, retry in %s)", err, len(pending), backoff)
		failed = true
		wait := time.NewTimer(backoff)
	sleep:
		for {
			select {
			case m := <-o.q:
				add(m)
			case <-wait.C:
				break sleep
			case <-ctx.Done():
				wait.Stop()
				o.log.Printf("notify: stopping with %d unsent message(s)", len(pending))
				return
			}
		}
		if backoff *= 2; backoff > o.max {
			backoff = o.max
		}
	}
}
