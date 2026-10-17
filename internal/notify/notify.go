// Package notify delivers rendered messages to the owner.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Notifier sends one message. Text is Telegram-HTML safe (see finding.Telegram).
type Notifier interface {
	Send(ctx context.Context, text string) error
}

// Multi fans out to every notifier and reports all failures together.
type Multi []Notifier

func (m Multi) Send(ctx context.Context, text string) error {
	var errs []error
	for _, n := range m {
		if err := n.Send(ctx, text); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stdout prints the message (HTML tags stripped) — used by `check` and for debugging.
type Stdout struct{ W io.Writer }

func (s Stdout) Send(_ context.Context, text string) error {
	_, err := fmt.Fprintln(s.W, StripHTML(text))
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
