package notify

import (
	"context"
	"time"
)

// Failover sends through Primary (the cloud) and switches to Fallback (direct Telegram)
// only after Primary has been failing for After (10 minutes in the daemon). One message
// per alert, never two: while Primary is merely slow to recover, the error goes back to
// the outbox, which retries the same message.
//
// Send is called only from the outbox goroutine, so the state needs no mutex.
type Failover struct {
	Primary  Notifier
	Fallback Notifier
	After    time.Duration
	Now      func() time.Time // default time.Now
	// OnSwitch, when set, is told once per outage that the fallback took over.
	OnSwitch func(err error)

	failingSince time.Time
	switched     bool
}

func (f *Failover) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Failover) Send(ctx context.Context, m Message) error {
	err := f.Primary.Send(ctx, m)
	if err == nil {
		f.failingSince, f.switched = time.Time{}, false
		return nil
	}
	now := f.now()
	if f.failingSince.IsZero() {
		f.failingSince = now
	}
	if now.Sub(f.failingSince) < f.After {
		return err
	}
	if !f.switched && f.OnSwitch != nil {
		f.OnSwitch(err)
	}
	f.switched = true
	if m.Text == "" { // cloud-only message (start-up report): nothing to show on Telegram
		return nil
	}
	return f.Fallback.Send(ctx, m)
}
