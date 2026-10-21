package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

type switchable struct {
	err  error
	sent []Message
}

func (s *switchable) Send(_ context.Context, m Message) error {
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, m)
	return nil
}

func TestFailover(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cloud := &switchable{err: errors.New("cloud down")}
	tg := &switchable{}
	switches := 0
	f := &Failover{Primary: cloud, Fallback: tg, After: 10 * time.Minute, Now: func() time.Time { return now },
		OnSwitch: func(error) { switches++ }}
	msg := Message{Kind: KindAlert, Text: "<b>alert</b>"}
	ctx := context.Background()

	if err := f.Send(ctx, msg); err == nil {
		t.Fatal("first failure must go back to the outbox")
	}
	now = now.Add(9 * time.Minute)
	if err := f.Send(ctx, msg); err == nil || len(tg.sent) != 0 {
		t.Fatal("after 9 minutes: still no fallback")
	}
	now = now.Add(2 * time.Minute) // 11 minutes failing
	if err := f.Send(ctx, msg); err != nil || len(tg.sent) != 1 {
		t.Fatalf("after 11 minutes: fallback must deliver (err=%v, sent=%d)", err, len(tg.sent))
	}
	if err := f.Send(ctx, Message{Kind: KindReport, Report: &cloudapi.Report{}}); err != nil || len(tg.sent) != 1 {
		t.Fatal("cloud-only message must be dropped, not sent to Telegram")
	}
	if switches != 1 {
		t.Errorf("OnSwitch called %d times, want 1", switches)
	}

	cloud.err = nil // recovery resets
	if err := f.Send(ctx, msg); err != nil || len(cloud.sent) != 1 {
		t.Fatal("recovered primary must deliver")
	}
	cloud.err = errors.New("down again")
	now = now.Add(time.Minute)
	if err := f.Send(ctx, msg); err == nil || len(tg.sent) != 1 {
		t.Fatal("a fresh outage must wait the full period again")
	}
}

type fakeCloud struct {
	events  []cloudapi.Event
	reports []cloudapi.Report
}

func (f *fakeCloud) PostEvents(_ context.Context, evs []cloudapi.Event) (int, error) {
	f.events = append(f.events, evs...)
	return len(evs), nil
}
func (f *fakeCloud) PostReport(_ context.Context, r cloudapi.Report) error {
	f.reports = append(f.reports, r)
	return nil
}

func TestCloudSink(t *testing.T) {
	fc := &fakeCloud{}
	c := &Cloud{Client: fc}
	ctx := context.Background()
	_ = c.Send(ctx, Message{Kind: KindAlert, Alert: &cloudapi.Event{UID: "u1"}, Text: "x"})
	_ = c.Send(ctx, Message{Kind: KindReport, Report: &cloudapi.Report{Host: "h"}})
	_ = c.Send(ctx, TextMessage("connected"))
	if len(fc.events) != 1 || fc.events[0].UID != "u1" || len(fc.reports) != 1 {
		t.Errorf("events=%v reports=%v", fc.events, fc.reports)
	}
}

func TestTextChannelsSkipCloudOnly(t *testing.T) {
	if err := (&Telegram{Token: "t", ChatID: "c", BaseURL: "http://127.0.0.1:1"}).Send(context.Background(), Message{Kind: KindReport}); err != nil {
		t.Errorf("telegram must skip an empty message without a request: %v", err)
	}
}
