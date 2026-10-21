package cloudapi

import (
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	in := Report{Host: "web-1", Time: now, Score: 85, AgentVersion: "v0.3.0",
		Findings: []Finding{{ID: "ssh.root_login", Severity: "high", Args: map[string]string{"a": "b"}, Fix: "sudo x",
			Text: map[string]Text{"he": {Title: "כותרת", Explain: "הסבר"}, "en": {Title: "Title", Explain: "Why"}}}},
		Listeners: []Listener{{Port: 22, Proto: "tcp", Bind: "0.0.0.0", Process: "sshd"}}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip:\n%+v\n%+v", in, out)
	}
	ev := Event{UID: "u1", Time: now, ID: "alert.bruteforce", Severity: "high", Text: map[string]Text{"en": {Title: "x"}}}
	b, _ = json.Marshal([]Event{ev})
	var evs []Event
	if err := json.Unmarshal(b, &evs); err != nil || !reflect.DeepEqual(evs[0], ev) {
		t.Errorf("events round trip: %v %+v", err, evs)
	}
}

var forbidden = regexp.MustCompile(`(?i)command|exec|run|script`)

// The cloud must never be able to tell an agent to do something. A response field whose
// name suggests an instruction fails the build.
func TestNoCommandFields(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] || typ.PkgPath() == "time" {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := path + "." + f.Name
			if forbidden.MatchString(f.Name) || forbidden.MatchString(f.Tag.Get("json")) {
				t.Errorf("response field %s looks like an instruction", name)
			}
			walk(f.Type, name)
		}
	}
	for _, r := range ResponseTypes {
		walk(reflect.TypeOf(r), reflect.TypeOf(r).Name())
	}
	if len(seen) < len(ResponseTypes) {
		t.Fatal("walker did not visit every response type")
	}
}

func TestWalkerCatchesABadField(t *testing.T) {
	type bad struct {
		RunScript string `json:"run_script"`
	}
	if !forbidden.MatchString(reflect.TypeOf(bad{}).Field(0).Name) {
		t.Fatal("pattern must match RunScript")
	}
}
