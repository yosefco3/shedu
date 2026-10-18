package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTelegramSend(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	tg := &Telegram{Token: "123:abc", ChatID: "42", BaseURL: srv.URL}
	if err := tg.Send(context.Background(), "<b>hi</b>"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot123:abc/sendMessage" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody["chat_id"] != "42" || gotBody["parse_mode"] != "HTML" || gotBody["text"] != "<b>hi</b>" || gotBody["disable_web_page_preview"] != true {
		t.Errorf("body = %v", gotBody)
	}
}

func TestTelegramError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
	}))
	defer srv.Close()
	err := (&Telegram{Token: "bad", ChatID: "1", BaseURL: srv.URL}).Send(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("err = %v", err)
	}
}

func TestTelegramSplitsLongMessages(t *testing.T) {
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		texts = append(texts, b["text"])
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	line := strings.Repeat("א", 99) + "\n" // 100 runes per line
	msg := strings.Repeat(line, 90)        // 9000 runes
	if err := (&Telegram{Token: "t", ChatID: "c", BaseURL: srv.URL}).Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if len(texts) != 3 {
		t.Fatalf("want 3 requests, got %d", len(texts))
	}
	for i, p := range texts {
		if utf8.RuneCountInString(p) > maxMessageRunes || !strings.HasSuffix(p, "\n") {
			t.Errorf("part %d: %d runes, ends on line boundary: %v", i, utf8.RuneCountInString(p), strings.HasSuffix(p, "\n"))
		}
	}
	if strings.Join(texts, "") != msg {
		t.Error("parts must concatenate back to the original")
	}
}

func TestSplitHugeLine(t *testing.T) {
	parts := Split(strings.Repeat("x", 25), 10)
	if len(parts) != 3 || parts[2] != "xxxxx" {
		t.Errorf("parts = %v", parts)
	}
}

type failing struct{}

func (failing) Send(context.Context, string) error { return errors.New("down") }

type recorder struct{ got []string }

func (r *recorder) Send(_ context.Context, s string) error { r.got = append(r.got, s); return nil }

func TestMulti(t *testing.T) {
	rec := &recorder{}
	err := Multi{failing{}, rec}.Send(context.Background(), "msg")
	if err == nil || !strings.Contains(err.Error(), "down") {
		t.Errorf("err = %v", err)
	}
	if len(rec.got) != 1 || rec.got[0] != "msg" {
		t.Errorf("second notifier must still be called: %v", rec.got)
	}
}

func TestStdoutStripsHTML(t *testing.T) {
	var sb strings.Builder
	_ = Stdout{W: &sb}.Send(context.Background(), "<b>a &lt;b&gt;</b> <code>c</code>")
	if sb.String() != "a <b> c\n" {
		t.Errorf("got %q", sb.String())
	}
}

func TestTelegramErrorHidesToken(t *testing.T) {
	tg := &Telegram{Token: "123456:SECRET-TOKEN", ChatID: "1", BaseURL: "http://127.0.0.1:1"} // nothing listens
	err := tg.Send(context.Background(), "hi")
	if err == nil {
		t.Fatal("want a connection error")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") || !strings.Contains(err.Error(), "<token>") {
		t.Errorf("token must be redacted: %v", err)
	}
}
