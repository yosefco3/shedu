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

	"github.com/yosefco3/shedu/internal/checks"
	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/daemon"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/watch"
	"log"
	"os/signal"
	"syscall"
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
		langFlag := fs.String("lang", "", "terminal language: en (default) or he; Telegram uses LANG from the config")
		asJSON := fs.Bool("json", false, "machine-readable output")
		cfgPath := fs.String("config", config.DefaultPath, "path to the config file")
		noTelegram := fs.Bool("no-telegram", false, "print only, do not send to Telegram")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "shedu:", err)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		report := checks.RunAll(ctx)
		if cfg.Hostname != "" {
			report.Host = cfg.Hostname
		}
		if *asJSON {
			b, err := finding.JSON(report)
			if err != nil {
				fmt.Fprintln(os.Stderr, "shedu:", err)
				return 1
			}
			fmt.Println(string(b))
			return 0
		}
		// Terminal output is English unless --lang says otherwise: terminals
		// render Hebrew right-to-left badly. Telegram gets the configured language.
		termLang := i18n.En
		if *langFlag != "" {
			termLang = i18n.Parse(*langFlag)
		}
		msgLang := cfg.Lang
		if env := os.Getenv("SHEDU_LANG"); env != "" {
			msgLang = i18n.Parse(env)
		}
		fmt.Print(finding.Text(report, termLang))
		if cfg.TelegramEnabled() && !*noTelegram {
			tg := &notify.Telegram{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID}
			if err := tg.Send(ctx, finding.Telegram(report, msgLang, 5)); err != nil {
				fmt.Fprintln(os.Stderr, "shedu:", err)
				return 1
			}
			fmt.Fprintln(os.Stderr, "sent to Telegram")
		}
		return 0
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		cfgPath := fs.String("config", config.DefaultPath, "path to the config file")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return runDaemon(*cfgPath)
	default:
		fmt.Fprintf(os.Stderr, "shedu: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

func runDaemon(cfgPath string) int {
	logger := log.New(os.Stderr, "", 0) // journald adds timestamps
	cfg, err := config.Load(cfgPath)
	if err != nil {
		logger.Println("shedu:", err)
		return 1
	}
	for _, w := range cfg.Warnings {
		logger.Println("shedu:", w)
	}
	st, err := watch.LoadState(cfg.StateDir)
	if err != nil {
		logger.Println("shedu:", err)
	}
	var notifier notify.Notifier = notify.Stdout{W: os.Stdout}
	if cfg.TelegramEnabled() {
		notifier = &notify.Telegram{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID}
	} else {
		logger.Println("shedu: Telegram not configured, alerts go to stdout (see /etc/shedu/guard.conf)")
		cfg.Lang = i18n.En // terminals render Hebrew badly
	}
	acc := watch.NewAccountsWatcher(cfg.StateDir)
	d := &daemon.Daemon{
		Cfg:      cfg,
		Notifier: notifier,
		Auth:     watch.NewSource(),
		Accounts: acc,
		Watchers: []watch.Runner{
			watch.NewProcWatcher(cfg.StateDir),
			watch.NewOutboundWatcher(cfg.StateDir, cfg.Thresholds, logger.Printf),
		},
		Rules:    watch.NewRules(cfg.BruteForceN),
		State:    st,
		RunCheck: checks.RunAll,
		Log:      logger,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Printf("shedu %s watching %s", version, cfg.Hostname)
	if err := d.Run(ctx); err != nil {
		logger.Println("shedu:", err)
		return 1
	}
	return 0
}
