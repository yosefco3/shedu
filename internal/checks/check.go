// Package checks contains the one-shot audits behind `shedu check`. Every check
// separates collection (reading files, running commands) from analysis (pure
// functions over bytes) so the analysis can be tested with fixtures and no root.
package checks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/yosefco12/shedu/internal/finding"
)

// Check inspects one aspect of the host. Run must never modify the system.
type Check interface {
	Name() string
	Run(ctx context.Context) ([]finding.Finding, error)
}

// Default returns the production checks in display order. Later steps append here.
func Default() []Check {
	return []Check{
		NewUpdates(),
	}
}

// RunAll runs the default checks against this host.
func RunAll(ctx context.Context) finding.Report {
	host, _ := os.Hostname()
	return Run(ctx, host, time.Now(), Default())
}

// Run executes the given checks. A check that returns an error becomes a single
// Info finding "check.failed" and never prevents the others from running.
func Run(ctx context.Context, host string, now time.Time, checks []Check) finding.Report {
	r := finding.Report{Host: host, Time: now, Findings: []finding.Finding{}}
	for _, c := range checks {
		fs, err := c.Run(ctx)
		if err != nil {
			r.Findings = append(r.Findings, finding.Finding{
				ID:       "check.failed",
				Severity: finding.Info,
				Args:     map[string]string{"name": c.Name(), "err": err.Error()},
			})
			continue
		}
		r.Findings = append(r.Findings, fs...)
	}
	return r
}

// isNotInstalled reports whether err means the command does not exist on this host.
func isNotInstalled(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}

// readFile is os.ReadFile with a nil result (no error) for a missing file, so
// callers can treat "absent" as "empty".
func readFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}
