package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// UID identifies this alert for idempotent delivery. It is derived from the alert itself
// (id, key, time, args), so every call returns the same value and a retried send is
// recognised by the cloud.
func (a Alert) UID() string {
	h := sha256.New()
	h.Write([]byte(a.ID + "\x00" + a.Key + "\x00" + strconv.FormatInt(a.Time.UnixNano(), 10)))
	keys := make([]string, 0, len(a.Args))
	for k := range a.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte("\x00" + k + "=" + a.Args[k]))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Cloud converts the alert to the public cloud schema, rendered in Hebrew and English.
func (a Alert) Cloud() cloudapi.Event {
	return cloudapi.Event{
		UID: a.UID(), Time: a.Time.UTC(), ID: a.ID, Severity: a.Severity.String(),
		Args: a.Args, Fix: a.Fix, Text: finding.Texts(a.ID, a.Args),
	}
}
