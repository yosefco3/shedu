package notify

import (
	"context"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// CloudClient is the part of cloud.Client the sink needs.
type CloudClient interface {
	PostEvents(ctx context.Context, evs []cloudapi.Event) (int, error)
	PostReport(ctx context.Context, r cloudapi.Report) error
}

// Cloud delivers structured messages to the Shedu cloud: an alert becomes POST /v1/events,
// a report POST /v1/report. Plain text messages have no cloud form and are skipped.
type Cloud struct{ Client CloudClient }

func (c *Cloud) Send(ctx context.Context, m Message) error {
	switch {
	case m.Kind == KindAlert && m.Alert != nil:
		_, err := c.Client.PostEvents(ctx, []cloudapi.Event{*m.Alert})
		return err
	case m.Kind == KindReport && m.Report != nil:
		return c.Client.PostReport(ctx, *m.Report)
	default:
		return nil
	}
}
