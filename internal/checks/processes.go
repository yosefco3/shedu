package checks

import (
	"context"
	"os"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/watch"
)

// Processes reports running programs that look like droppers: started from a
// temporary folder, or whose binary was deleted while running.
type Processes struct {
	Inventory func() ([]watch.Process, error)
	UserName  func(uid int) string
	IsRoot    bool // without root, other users' processes cannot be inspected
}

// NewProcesses returns the production collector.
func NewProcesses() *Processes {
	return &Processes{Inventory: watch.OSInventory, UserName: watch.LookupUser, IsRoot: os.Geteuid() == 0}
}

func (p *Processes) Name() string { return "processes" }

func (p *Processes) Run(ctx context.Context) ([]finding.Finding, error) {
	procs, err := p.Inventory()
	if err != nil {
		return nil, err
	}
	var fs []finding.Finding
	for _, pr := range procs {
		reason := watch.SuspiciousExec(pr)
		if reason == "" {
			continue
		}
		args := watch.ProcArgs(pr, p.UserName)
		fs = append(fs, finding.Finding{
			ID: "proc." + reason, Severity: finding.High, Args: args,
			Fix: watch.ProcFix(reason, args["pid"]), Evidence: pr.Exe,
		})
	}
	if !p.IsRoot {
		fs = append(fs, finding.Finding{ID: "proc.need_root", Severity: finding.Info})
	}
	return fs, nil
}
