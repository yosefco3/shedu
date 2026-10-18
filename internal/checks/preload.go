package checks

import (
	"context"
	"io/fs"
	"os"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/watch"
)

// Preload looks for injected libraries: /etc/ld.so.preload, and running
// programs started with an LD_PRELOAD from outside the system folders.
type Preload struct {
	Root      fs.FS // the host's /
	Proc      fs.FS // /proc
	Inventory func() ([]watch.Process, error)
	UserName  func(uid int) string
}

// NewPreload returns the production collector.
func NewPreload() *Preload {
	return &Preload{Root: os.DirFS("/"), Proc: os.DirFS("/proc"), Inventory: watch.OSInventory, UserName: watch.LookupUser}
}

func (p *Preload) Name() string { return "preload" }

func (p *Preload) Run(ctx context.Context) ([]finding.Finding, error) {
	var fs []finding.Finding
	if content := watch.ScanPreloadFile(p.Root); content != "" {
		fs = append(fs, finding.Finding{ID: "preload.file", Severity: finding.Critical,
			Args: map[string]string{"content": content}, Fix: watch.PreloadFix, Evidence: content})
	}
	procs, err := p.Inventory()
	if err != nil {
		return fs, nil // the file check still stands
	}
	found := watch.PreloadedProcs(p.Proc, procs)
	for _, pr := range procs {
		v, ok := found[pr.PID]
		if !ok {
			continue
		}
		args := watch.ProcArgs(pr, p.UserName)
		args["value"] = v
		fs = append(fs, finding.Finding{ID: "preload.env", Severity: finding.High, Args: args,
			Fix: watch.PreloadEnvFix(args["pid"]), Evidence: "LD_PRELOAD=" + v})
	}
	return fs, nil
}
