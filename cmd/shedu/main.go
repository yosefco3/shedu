// Command shedu is a plain-language security guard for small Linux servers.
//
//	shedu check [--lang he|en] [--json]   one-shot audit of this host
//	shedu run   [--config PATH]           background watcher (systemd service)
//	shedu version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yosefco12/shedu/internal/checks"
	"github.com/yosefco12/shedu/internal/finding"
	"github.com/yosefco12/shedu/internal/i18n"
)

// version is injected at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func usage() {
	fmt.Fprintln(os.Stderr, "usage: shedu <check|run|version> [flags]")
	fmt.Fprintln(os.Stderr, "  check   audit this server once and print a scored report")
	fmt.Fprintln(os.Stderr, "  run     watch logins and accounts, send alerts (daemon)")
	fmt.Fprintln(os.Stderr, "  version print the version")
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "check":
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		langFlag := fs.String("lang", "", "message language: he or en (default $SHEDU_LANG or he)")
		asJSON := fs.Bool("json", false, "machine-readable output")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		report := checks.RunAll(ctx)
		if *asJSON {
			b, err := finding.JSON(report)
			if err != nil {
				fmt.Fprintln(os.Stderr, "shedu:", err)
				return 1
			}
			fmt.Println(string(b))
			return 0
		}
		lang := *langFlag
		if lang == "" {
			lang = os.Getenv("SHEDU_LANG")
		}
		fmt.Print(finding.Text(report, i18n.Parse(lang)))
		return 0
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.String("config", "/etc/shedu/guard.conf", "path to the config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		fmt.Fprintln(os.Stderr, "shedu run: not implemented yet")
		return 2
	default:
		fmt.Fprintf(os.Stderr, "shedu: unknown command %q\n", args[0])
		usage()
		return 2
	}
}
