// Package cloudapi is the complete, public schema of what a Shedu agent sends to the
// optional Shedu cloud, and of what the cloud answers. Nothing else ever leaves the
// server: if a field is not declared here, it is not sent.
//
// The cloud's answers are display-only data. No response type carries anything the agent
// could execute; TestNoCommandFields enforces that.
package cloudapi

import "time"

// Version is the schema version, sent in the X-Shedu-Schema header of every request.
const Version = 1

// Header names used by the client.
const (
	SchemaHeader = "X-Shedu-Schema"
)

// API paths, relative to the cloud URL.
const (
	PathEnroll    = "/v1/enroll"
	PathReport    = "/v1/report"
	PathEvents    = "/v1/events"
	PathHeartbeat = "/v1/heartbeat"
	// PathDisconnect is sent by `shedu enroll --off` (empty body, with the key, before the
	// key is removed): the cloud marks the server "disconnected by the admin" and revokes
	// the key, instead of reporting it as silent.
	PathDisconnect = "/v1/disconnect"
)

// Limits the cloud enforces; the agent stays under them.
const (
	MaxFindings  = 500 // per report
	MaxEvents    = 100 // per POST /v1/events
	MaxBodyBytes = 1 << 20
)

// Text is one rendered message: the same title and explanation the owner sees on Telegram.
type Text struct {
	Title   string `json:"title"`
	Explain string `json:"explain"`
}

// Finding is one result of `shedu check`, exactly as `shedu check --json` prints it, plus
// the rendered texts keyed by language ("he", "en").
type Finding struct {
	ID       string            `json:"id"`
	Severity string            `json:"severity"` // info | low | medium | high | critical
	Args     map[string]string `json:"args,omitempty"`
	Fix      string            `json:"fix,omitempty"`
	Evidence string            `json:"evidence,omitempty"`
	Text     map[string]Text   `json:"text"`
}

// Listener is one TCP port reachable from outside the host (what the ports.summary
// finding lists). Bind is the address (0.0.0.0, ::, a public IP), Process is the short
// process name (comm), never its command line.
type Listener struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"` // tcp | tcp6
	Bind    string `json:"bind"`
	Process string `json:"process,omitempty"`
}

// Report is one full check run: at start-up, in the daily report, and after a manual check.
type Report struct {
	Host         string     `json:"host"`
	Time         time.Time  `json:"time"`
	Score        int        `json:"score"`
	AgentVersion string     `json:"agent_version"`
	Findings     []Finding  `json:"findings"`
	Listeners    []Listener `json:"listeners"`
}

// Event is one alert, the same one that goes to Telegram. UID is unique per alert so a
// re-sent event is stored once.
type Event struct {
	UID      string            `json:"uid"`
	Time     time.Time         `json:"time"`
	ID       string            `json:"id"`
	Severity string            `json:"severity"`
	Args     map[string]string `json:"args,omitempty"`
	Fix      string            `json:"fix,omitempty"`
	Text     map[string]Text   `json:"text"`
}

// EnrollRequest trades a one-time enrollment token for a permanent server key.
type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`   // e.g. "Ubuntu 24.04.1 LTS" (PRETTY_NAME of /etc/os-release)
	Arch         string `json:"arch"` // GOARCH
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse is returned once; the cloud keeps only a hash of Key.
type EnrollResponse struct {
	ServerID string `json:"server_id"`
	Key      string `json:"key"` // shk_<server_id>_<secret>
	URL      string `json:"url"` // the API URL to store as CLOUD_URL
}

// Heartbeat is sent every 5 minutes. It is not stored; it moves "last seen".
type Heartbeat struct {
	Time           time.Time `json:"time"`
	AgentVersion   string    `json:"agent_version"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	Watchers       []string  `json:"watchers"`
	DirectTelegram bool      `json:"direct_telegram"`
	Addrs          []string  `json:"addrs"` // non-loopback interface addresses
	Lang           string    `json:"lang"`
}

// HeartbeatResponse is display-only: the agent logs it, it never acts on it.
type HeartbeatResponse struct {
	LatestVersion string `json:"latest_version"`
}

// EventsResponse reports how many events were new (re-sent ones are not counted).
type EventsResponse struct {
	Accepted int `json:"accepted"`
}

// ErrorResponse is the body of every non-2xx answer.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ResponseTypes lists every type the cloud sends back to the agent.
var ResponseTypes = []any{EnrollResponse{}, HeartbeatResponse{}, EventsResponse{}, ErrorResponse{}}
