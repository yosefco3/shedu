package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/yosefco3/shedu/internal/update"
	semver "github.com/yosefco3/shedu/internal/version"
)

// Test seams: tests point the updater at local servers and pretend to be root.
var (
	configureUpdater = func(*update.Updater) {}
	isRoot           = func() bool { return os.Geteuid() == 0 }
)

// runUpgrade is `shedu upgrade [--check] [--version vX.Y.Z] [--auto]`. Exit codes: 0 updated
// or already up to date, 1 failed (nothing changed, or rolled back), 2 usage.
//
// --auto is how the daemon runs it at night, in a transient systemd unit: no downgrade
// even with --version, and the outcome goes to /var/lib/shedu/update/result.json, which
// the daemon turns into an agent.updated or agent.update_failed event.
func runUpgrade(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	check := fs.Bool("check", false, "only print the current and latest version; change nothing")
	want := fs.String("version", "", "install this release (vX.Y.Z) instead of the latest")
	auto := fs.Bool("auto", false, "run by the daemon: only a newer release, outcome written for the daemon")
	// Accepted for symmetry with the other commands; upgrade reads no config.
	fs.String("config", "", "ignored")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *want != "" && !update.ValidVersion(*want) {
		fmt.Fprintf(os.Stderr, "shedu: --version %q is not a release version (vX.Y.Z)\n", *want)
		return 2
	}
	u := newUpdater()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// fail prints why nothing (or the rollback) happened; in --auto mode it is also the
	// reason in the result file.
	result := update.RunResult{From: version, Version: *want}
	fail := func(format string, a ...any) int {
		result.Reason = fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, "shedu: "+result.Reason)
		return 1
	}
	if *auto && !*check {
		defer func() {
			result.At = time.Now().UTC()
			if err := update.WriteResult(u.Dir, result); err != nil {
				fmt.Fprintln(os.Stderr, "shedu: could not write the result for the daemon:", err)
			}
		}()
	}

	target := *want
	if target == "" {
		lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
		latest, err := u.Latest(lctx)
		lcancel()
		if err != nil {
			return fail("%v", err)
		}
		target = latest
	}
	result.Version = target
	keyErr := u.CheckKey()

	if *check {
		fmt.Printf("current %s, latest %s\n", version, target)
		switch {
		case version == "dev":
			fmt.Println("this is a development build; install a release with: sudo shedu upgrade --version " + target)
		case semver.Newer(target, version) && keyErr == nil:
			fmt.Println("an update is available: sudo shedu upgrade")
		case semver.Newer(target, version):
			fmt.Println("an update is available")
		default:
			fmt.Println("up to date")
		}
		if keyErr != nil {
			fmt.Println("note:", keyErr)
		}
		return 0
	}

	if keyErr != nil {
		return fail("%v", keyErr)
	}
	if *auto && (version == "dev" || !semver.Newer(target, version)) {
		// The daemon passes only newer versions; this also covers a race with a manual upgrade.
		result.OK, result.UpToDate = true, true
		fmt.Printf("up to date: running %s, latest is %s\n", version, target)
		return 0
	}
	if *auto {
		if at, ok := update.RecentFailure(u.Dir, target, time.Now()); ok {
			result.OK, result.Skipped = true, true
			result.Reason = fmt.Sprintf("%s failed at %s; tried again after %s", target,
				at.Local().Format("2006-01-02 15:04"), at.Add(update.RetryAfter).Local().Format("2006-01-02 15:04"))
			fmt.Println("skipped:", result.Reason)
			return 0
		}
		defer func() {
			if result.OK {
				update.ClearFailure(u.Dir)
			} else {
				update.RecordFailure(u.Dir, target, time.Now()) //nolint:errcheck
			}
		}()
	}
	switch {
	case target == version:
		fmt.Printf("already running %s; nothing to do\n", version)
		return 0
	case *want == "" && version != "dev" && !semver.Newer(target, version):
		fmt.Printf("up to date: running %s, latest is %s\n", version, target)
		return 0
	}
	if *want != "" && version != "dev" && semver.Newer(version, target) {
		fmt.Printf("note: %s is older than the running %s; installing it as asked\n", target, version)
		if !semver.Newer(target, "v0.3.0") {
			fmt.Println("note: versions before v0.3.1 refuse a guard.conf with AUTO_UPDATE or AUTO_UPDATE_AT; remove those lines from /etc/shedu/guard.conf first")
		}
	}
	if !isRoot() {
		return fail("upgrade replaces /usr/local/bin/shedu and restarts the service; run it with sudo")
	}

	unlock, err := u.Lock()
	if err != nil {
		return fail("%v", err)
	}
	defer unlock()
	fmt.Printf("downloading shedu %s...\n", target)
	bin, err := u.Fetch(ctx, target, u.Arch)
	if err != nil {
		return fail("%v; nothing was changed", err)
	}
	dir := filepath.Dir(bin)
	if err := u.Verify(filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig"), bin, target); err != nil {
		os.Remove(bin) //nolint:errcheck
		return fail("%v; nothing was changed", err)
	}
	fmt.Println("✔ release signature and checksum verified")
	// From here on a closed SSH session or Ctrl-C must not stop a swap or a rollback halfway.
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Reset(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	res, err := u.Apply(ctx, bin, target)
	switch {
	case errors.Is(err, update.ErrRolledBack), errors.Is(err, update.ErrRollbackDown):
		result.RolledBack = true
		code := fail("%v", err)
		fmt.Fprintln(os.Stderr, "see why with: sudo journalctl -u shedu -n 50")
		return code
	case err != nil:
		return fail("%v", err)
	}
	result.OK = true
	bp := u.BinPath
	fmt.Printf("✔ installed %s %s (the previous one is kept as %s.prev)\n", bp, target, bp)
	if res.NotRunning {
		fmt.Println("the shedu service is not running, so it was not restarted; start it with: sudo systemctl start shedu")
	} else {
		fmt.Printf("✔ the shedu service restarted on %s\n", target)
	}
	return 0
}

// newUpdater asks GitHub for the latest release. It deliberately does not ask the cloud:
// that would mean sending a heartbeat, which would make a server whose daemon is down
// look alive in the dashboard. (The daemon already gets the cloud's answer with its own
// heartbeat.)
func newUpdater() *update.Updater {
	u := &update.Updater{
		UserAgent: "shedu-agent/" + version,
		BinPath:   update.DefaultBinPath,
	}
	configureUpdater(u)
	if u.Arch == "" {
		u.Arch = runtime.GOARCH
	}
	return u
}
