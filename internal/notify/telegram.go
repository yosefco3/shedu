package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Telegram sends messages through the Bot API with a single HTTP call per message.
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string       // default https://api.telegram.org; tests point it at httptest
	Client  *http.Client // default: 10s timeout
}

// maxMessageRunes stays under Telegram's 4096 limit with room for the HTML tags
// the split may leave open.
const maxMessageRunes = 4000

func (t *Telegram) Send(ctx context.Context, m Message) error {
	if m.Text == "" { // cloud-only message
		return nil
	}
	for _, part := range Split(m.Text, maxMessageRunes) {
		if err := t.sendOne(ctx, part); err != nil {
			return err
		}
	}
	return nil
}

func (t *Telegram) sendOne(ctx context.Context, text string) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// net/http errors quote the full URL, and the URL holds the bot token.
		return fmt.Errorf("telegram: %s", t.redact(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var apiErr struct {
		Description string `json:"description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(raw, &apiErr)
	if apiErr.Description == "" {
		apiErr.Description = strings.TrimSpace(string(raw))
	}
	return fmt.Errorf("telegram: HTTP %d: %s", resp.StatusCode, apiErr.Description)
}

// redact removes the bot token from s so it never reaches a log.
func (t *Telegram) redact(s string) string {
	if t.Token == "" {
		return s
	}
	return strings.ReplaceAll(s, t.Token, "<token>")
}

// Split cuts text into chunks of at most max runes, breaking on line boundaries
// whenever possible so a finding is never torn in half mid-command.
func Split(text string, max int) []string {
	if utf8.RuneCountInString(text) <= max {
		return []string{text}
	}
	var parts []string
	var cur strings.Builder
	curLen := 0
	for _, line := range strings.SplitAfter(text, "\n") {
		n := utf8.RuneCountInString(line)
		if n > max { // a single enormous line: hard-cut it
			if curLen > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
				curLen = 0
			}
			r := []rune(line)
			for len(r) > max {
				parts = append(parts, string(r[:max]))
				r = r[max:]
			}
			line, n = string(r), len(r)
		}
		if curLen+n > max && curLen > 0 {
			parts = append(parts, cur.String())
			cur.Reset()
			curLen = 0
		}
		cur.WriteString(line)
		curLen += n
	}
	if curLen > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}
