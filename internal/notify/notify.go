// Package notify delivers rendered messages to the owner.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// Message kinds.
const (
	KindAlert  = "alert"  // Alert is set
	KindReport = "report" // Report is set
	KindText   = "text"   // only Text (start-up notice and the like)
)

// Message is one notification. Text is always set and is what Telegram and stdout show;
// the structured part is what the cloud receives, so the same alert can go either way.
type Message struct {
	UID    string // unique per message, for idempotent delivery
	Kind   string
	Text   string // Telegram-HTML safe (see finding.Telegram); "" = cloud-only, text channels skip it
	Alert  *cloudapi.Event
	Report *cloudapi.Report
}

// TextMessage wraps plain Telegram-HTML text.
func TextMessage(text string) Message { return Message{Kind: KindText, Text: text} }

// Notifier sends one message.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// Multi fans out to every notifier and reports all failures together.
type Multi []Notifier

func (m Multi) Send(ctx context.Context, msg Message) error {
	var errs []error
	for _, n := range m {
		if err := n.Send(ctx, msg); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stdout prints the message (HTML tags stripped) — used by `check` and for debugging.
type Stdout struct{ W io.Writer }

func (s Stdout) Send(_ context.Context, m Message) error {
	if m.Text == "" {
		return nil
	}
	_, err := fmt.Fprintln(s.W, StripHTML(m.Text))
	return err
}

// StripHTML removes the few tags finding.Telegram emits and unescapes entities.
func StripHTML(s string) string {
	r := strings.NewReplacer("<b>", "", "</b>", "", "<code>", "", "</code>", "", "<i>", "", "</i>", "",
		"&lt;", "<", "&gt;", ">", "&amp;", "&")
	return r.Replace(s)
}

// Escape makes arbitrary text safe inside a Telegram HTML message.
func Escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
