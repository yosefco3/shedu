package main

import "testing"

func TestRunExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, 2},
		{[]string{"version"}, 0},
		{[]string{"run"}, 2},
		{[]string{"bogus"}, 2},
		{[]string{"check", "--no-such-flag"}, 2},
	}
	for _, c := range cases {
		if got := run(c.args); got != c.want {
			t.Errorf("run(%v) = %d, want %d", c.args, got, c.want)
		}
	}
}
