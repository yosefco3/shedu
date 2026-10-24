package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

const fakeKey = "shk_testserver01_fakesecretvalue" // secret-scan: allow

type seen struct {
	path, auth, ua, schema string
	body                   []byte
}

func server(t *testing.T, status int, reply string, got *[]seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = append(*got, seen{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("User-Agent"), r.Header.Get(cloudapi.SchemaHeader), b})
		w.WriteHeader(status)
		io.WriteString(w, reply) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEveryCallSendsAuthAndUserAgent(t *testing.T) {
	var got []seen
	srv := server(t, 200, `{"accepted":1,"latest_version":"v0.3.1"}`, &got)
	var logs []string
	c := &Client{BaseURL: srv.URL + "/", Key: fakeKey, Version: "v0.3.0",
		Logf: func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }}
	ctx := context.Background()
	if err := c.PostReport(ctx, cloudapi.Report{Host: "web-1"}); err != nil {
		t.Fatal(err)
	}
	n, err := c.PostEvents(ctx, []cloudapi.Event{{UID: "u1", Time: time.Now()}})
	if err != nil || n != 1 {
		t.Fatalf("events: %d %v", n, err)
	}
	hb, err := c.Heartbeat(ctx, cloudapi.Heartbeat{AgentVersion: "v0.3.0"})
	if err != nil || hb.LatestVersion != "v0.3.1" {
		t.Fatalf("heartbeat: %+v %v", hb, err)
	}
	wantPaths := []string{"/v1/report", "/v1/events", "/v1/heartbeat"}
	for i, s := range got {
		if s.path != wantPaths[i] || s.auth != "Bearer "+fakeKey || s.ua != "shedu/v0.3.0" || s.schema != "1" {
			t.Errorf("request %d: %+v", i, s)
		}
	}
	var evs []cloudapi.Event
	if err := json.Unmarshal(got[1].body, &evs); err != nil || len(evs) != 1 || evs[0].UID != "u1" {
		t.Errorf("events body: %s", got[1].body)
	}
	if strings.Join(logs, "|") != "cloud: POST /v1/report 200|cloud: POST /v1/events 200|cloud: POST /v1/heartbeat 200" {
		t.Errorf("log lines: %q", logs)
	}
}

func TestEnrollWithoutKey(t *testing.T) {
	var got []seen
	srv := server(t, 200, `{"server_id":"abc","key":"shk_abc_x","url":"https://api.example.test"}`, &got)
	c := &Client{BaseURL: srv.URL}
	resp, err := c.Enroll(context.Background(), cloudapi.EnrollRequest{Token: "set_x", Hostname: "web-1"})
	if err != nil || resp.ServerID != "abc" || resp.Key != "shk_abc_x" {
		t.Fatalf("%+v %v", resp, err)
	}
	if got[0].auth != "" || got[0].path != "/v1/enroll" || !strings.Contains(string(got[0].body), `"token":"set_x"`) {
		t.Errorf("enroll request: %+v", got[0])
	}
}

func TestErrorsNeverContainTheKey(t *testing.T) {
	var got []seen
	srv := server(t, 401, `{"error":"invalid key `+fakeKey+`"}`, &got)
	c := &Client{BaseURL: srv.URL, Key: fakeKey}
	err := c.PostReport(context.Background(), cloudapi.Report{})
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), fakeKey) {
		t.Fatalf("error: %v", err)
	}
	// transport error with the key in the URL
	c = &Client{BaseURL: "http://127.0.0.1:1/" + fakeKey, Key: fakeKey}
	if err := c.PostReport(context.Background(), cloudapi.Report{}); err == nil || strings.Contains(err.Error(), fakeKey) {
		t.Fatalf("transport error: %v", err)
	}
}

func TestDefaultURL(t *testing.T) {
	if DefaultURL != "https://api.getshedu.com" {
		t.Fatal(DefaultURL)
	}
}

func TestRefusesPlainHTTPOverTheNetwork(t *testing.T) {
	for _, base := range []string{"http://api.example.com", "http://10.0.0.5:8080", "ftp://x", "not a url"} {
		c := &Client{BaseURL: base, Key: fakeKey}
		err := c.PostReport(context.Background(), cloudapi.Report{})
		if err == nil || strings.Contains(err.Error(), fakeKey) {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{"https://api.getshedu.com", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:1"} {
		if err := checkURL(base); err != nil {
			t.Errorf("%s must be allowed: %v", base, err)
		}
	}
}

func TestDisconnect(t *testing.T) {
	var got []seen
	srv := server(t, 200, `{}`, &got)
	if err := (&Client{BaseURL: srv.URL, Key: fakeKey}).Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].path != "/v1/disconnect" || got[0].auth != "Bearer "+fakeKey {
		t.Errorf("request: %+v", got)
	}
}
