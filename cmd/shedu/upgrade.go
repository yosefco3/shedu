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

// runUpgrade is `shedu upgrade [--check] [--version vX.Y.Z]`. Exit codes: 0 updated or
// already up to date, 1 failed (nothing changed, or rolled back), 2 usage.
func runUpgrade(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	check := fs.Bool("check", false, "only print the current and latest version; change nothing")
	want := fs.String("version", "", "install this release (vX.Y.Z) instead of the latest")
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

	target := *want
	if target == "" {
		lctx, lcancel := context.WithTimeout(ctx, 30*time.Second)
		latest, err := u.Latest(lctx)
		lcancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "shedu:", err)
			return 1
		}
		target = latest
	}
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
		fmt.Fprintln(os.Stderr, "shedu:", keyErr)
		return 1
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
	}
	if !isRoot() {
		fmt.Fprintln(os.Stderr, "shedu: upgrade replaces /usr/local/bin/shedu and restarts the service; run it with sudo")
		return 1
	}

	unlock, err := u.Lock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "shedu:", err)
		return 1
	}
	defer unlock()
	fmt.Printf("downloading shedu %s...\n", target)
	bin, err := u.Fetch(ctx, target, u.Arch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shedu: %v\nnothing was changed\n", err)
		return 1
	}
	dir := filepath.Dir(bin)
	if err := u.Verify(filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig"), bin, target); err != nil {
		os.Remove(bin) //nolint:errcheck
		fmt.Fprintf(os.Stderr, "shedu: %v\nnothing was changed\n", err)
		return 1
	}
	fmt.Println("✔ release signature and checksum verified")
	// From here on a closed SSH session or Ctrl-C must not stop a swap or a rollback halfway.
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Reset(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	res, err := u.Apply(ctx, bin, target)
	switch {
	case errors.Is(err, update.ErrRolledBack), errors.Is(err, update.ErrRollbackDown):
		fmt.Fprintln(os.Stderr, "shedu:", err)
		fmt.Fprintln(os.Stderr, "see why with: sudo journalctl -u shedu -n 50")
		return 1
	case err != nil:
		fmt.Fprintln(os.Stderr, "shedu:", err)
		return 1
	}
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
