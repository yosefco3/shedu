// Package cloud is the agent's thin HTTP client for the optional Shedu cloud. It only
// sends what pkg/cloudapi declares, over outbound HTTPS, and it never acts on an answer
// beyond reading the display-only fields.
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// DefaultURL is the cloud API used when CLOUD_URL is not set.
const DefaultURL = "https://api.getshedu.com"

// Client talks to one cloud URL with one server key. TLS uses the system CA store.
type Client struct {
	BaseURL string // default DefaultURL
	Key     string // shk_...; empty only for Enroll
	Version string // agent version, sent as User-Agent shedu/<version>
	HTTP    *http.Client
	// Logf, when set, receives one line per request: "cloud: POST /v1/events 200".
	// Never the body, never the key.
	Logf func(format string, args ...any)
}

// Enroll trades a one-time token for a permanent key. It needs no Key.
func (c *Client) Enroll(ctx context.Context, req cloudapi.EnrollRequest) (cloudapi.EnrollResponse, error) {
	var out cloudapi.EnrollResponse
	err := c.do(ctx, cloudapi.PathEnroll, req, &out)
	return out, err
}

// PostReport sends one check report.
func (c *Client) PostReport(ctx context.Context, r cloudapi.Report) error {
	return c.do(ctx, cloudapi.PathReport, r, nil)
}

// PostEvents sends alerts and returns how many were new.
func (c *Client) PostEvents(ctx context.Context, evs []cloudapi.Event) (int, error) {
	var out cloudapi.EventsResponse
	err := c.do(ctx, cloudapi.PathEvents, evs, &out)
	return out.Accepted, err
}

// Heartbeat reports that the agent is alive.
func (c *Client) Heartbeat(ctx context.Context, hb cloudapi.Heartbeat) (cloudapi.HeartbeatResponse, error) {
	var out cloudapi.HeartbeatResponse
	err := c.do(ctx, cloudapi.PathHeartbeat, hb, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("cloud: %s: %w", path, err)
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultURL
	}
	if err := checkURL(base); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cloud: %s", c.redact(err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "shedu/"+c.version())
	req.Header.Set(cloudapi.SchemaHeader, fmt.Sprint(cloudapi.Version))
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		c.logf("cloud: POST %s failed", path)
		return fmt.Errorf("cloud: POST %s: %s", path, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	c.logf("cloud: POST %s %d", path, resp.StatusCode)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("cloud: POST %s: read: %s", path, c.redact(err.Error()))
	}
	if resp.StatusCode/100 != 2 {
		var e cloudapi.ErrorResponse
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
			if len(e.Error) > 200 {
				e.Error = e.Error[:200]
			}
		}
		return fmt.Errorf("cloud: POST %s: HTTP %d: %s", path, resp.StatusCode, c.redact(e.Error))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("cloud: POST %s: bad response: %w", path, err)
		}
	}
	return nil
}

// checkURL allows https, and plain http only to this machine (local development), so the
// server key never travels in clear text over a network.
func checkURL(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("cloud: invalid CLOUD_URL %q", base)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("cloud: refusing %s: CLOUD_URL must use https (plain http only to localhost)", u.Redacted())
}

func (c *Client) version() string {
	if c.Version == "" {
		return "dev"
	}
	return c.Version
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// redact removes the server key from s so it never reaches a log.
func (c *Client) redact(s string) string {
	if c.Key == "" {
		return s
	}
	return strings.ReplaceAll(s, c.Key, "<key>")
}
