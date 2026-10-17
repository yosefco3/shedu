package finding

import "testing"

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{Info: "info", Low: "low", Medium: "medium", High: "high", Critical: "critical", Severity(9): "unknown"}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		name string
		sevs []Severity
		want int
	}{
		{"empty report", nil, 100},
		{"info only", []Severity{Info, Info}, 100},
		{"critical and medium", []Severity{Critical, Medium}, 62},
		{"one of each", []Severity{Info, Low, Medium, High, Critical}, 44},
		{"floor at zero", []Severity{Critical, Critical, Critical, Critical}, 0},
	}
	for _, c := range cases {
		r := Report{}
		for _, s := range c.sevs {
			r.Findings = append(r.Findings, Finding{ID: "x", Severity: s})
		}
		if got := r.Score(); got != c.want {
			t.Errorf("%s: Score() = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSorted(t *testing.T) {
	r := Report{Findings: []Finding{
		{ID: "b.low", Severity: Low},
		{ID: "z.crit", Severity: Critical},
		{ID: "a.low", Severity: Low},
		{ID: "m.high", Severity: High},
	}}
	got := r.Sorted()
	wantIDs := []string{"z.crit", "m.high", "a.low", "b.low"}
	for i, id := range wantIDs {
		if got[i].ID != id {
			t.Fatalf("Sorted()[%d] = %q, want %q (full: %v)", i, got[i].ID, id, got)
		}
	}
	if r.Findings[0].ID != "b.low" {
		t.Errorf("Sorted() must not mutate the original slice")
	}
}
