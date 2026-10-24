// Command shedu is a plain-language security guard for small Linux servers.
//
//	shedu check [--lang he|en] [--json]   one-shot audit of this host
//	shedu run   [--config PATH]           background watcher (systemd service)
//	shedu enroll <token> [--url URL]      connect this server to the Shedu cloud
//	shedu enroll --off                    disconnect it again
//	shedu upgrade [--check] [--version V] install the latest signed release
//	shedu version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yosefco3/shedu/internal/checks"
	"github.com/yosefco3/shedu/internal/cloud"
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
	fmt.Fprintln(os.Stderr, "usage: shedu <check|run|enroll|upgrade|version> [flags]")
	fmt.Fprintln(os.Stderr, "  check   audit this server once and print a scored report")
	fmt.Fprintln(os.Stderr, "  run     watch logins and accounts, send alerts (daemon)")
	fmt.Fprintln(os.Stderr, "  enroll  connect this server to the Shedu cloud (enroll --off to disconnect)")
	fmt.Fprintln(os.Stderr, "  upgrade install the latest signed release (upgrade --check only looks)")
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
		noCloud := fs.Bool("no-cloud", false, "do not send the report to the Shedu cloud")
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
		if cfg.CloudEnabled() && !*noCloud {
			c := &cloud.Client{BaseURL: cfg.CloudURL, Key: cfg.CloudKey, Version: version}
			if err := c.PostReport(ctx, finding.Cloud(report, version)); err != nil {
				fmt.Fprintln(os.Stderr, "shedu:", err)
			} else {
				fmt.Fprintln(os.Stderr, "sent to the Shedu cloud")
			}
		}
		// Enrolled servers get the report on Telegram from the cloud's bot, not directly.
		if cfg.TelegramEnabled() && !cfg.CloudEnabled() && !*noTelegram {
			tg := &notify.Telegram{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID}
			if err := tg.Send(ctx, notify.TextMessage(finding.Telegram(report, msgLang, 5))); err != nil {
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
	case "enroll":
		return runEnroll(args[1:])
	case "upgrade":
		return runUpgrade(args[1:])
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
	notifier, cloudClient := buildNotifier(cfg, logger)
	if !cfg.TelegramEnabled() && !cfg.CloudEnabled() {
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
			watch.NewProcWatcher(cfg.StateDir, cfg.Thresholds),
			watch.NewOutboundWatcher(cfg.StateDir, cfg.Thresholds, logger.Printf),
			watch.NewPersistenceWatcher(cfg.StateDir),
			watch.NewMassFileWatcher(cfg.Thresholds),
			watch.NewPreloadWatcher(cfg.StateDir),
			watch.NewClamWatcher(cfg.Thresholds.ClamAVAt, logger.Printf),
		},
		Rules:    watch.NewRules(cfg.BruteForceN),
		State:    st,
		RunCheck: checks.RunAll,
		Log:      logger,
		Version:  version,
	}
	if cloudClient != nil {
		d.Cloud = cloudClient
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

// buildNotifier routes alerts. Enrolled ⇒ the cloud sends them (official bot + email),
// and direct Telegram, if configured, takes over only after 10 minutes of cloud failure.
// Not enrolled ⇒ exactly as before: direct Telegram, or stdout.
func buildNotifier(cfg config.Config, logger *log.Logger) (notify.Notifier, *cloud.Client) {
	var tg notify.Notifier
	if cfg.TelegramEnabled() {
		tg = &notify.Telegram{Token: cfg.TelegramToken, ChatID: cfg.TelegramChatID}
	}
	if !cfg.CloudEnabled() {
		logger.Println("shedu: cloud: off")
		if tg != nil {
			return tg, nil
		}
		return notify.Stdout{W: os.Stdout}, nil
	}
	c := &cloud.Client{BaseURL: cfg.CloudURL, Key: cfg.CloudKey, Version: version, Logf: logger.Printf}
	sink := &notify.Cloud{Client: c}
	logger.Printf("shedu: cloud: on (%s)", cfg.CloudURL)
	if tg == nil {
		return sink, c
	}
	return &notify.Failover{Primary: sink, Fallback: tg, After: 10 * time.Minute,
		OnSwitch: func(err error) {
			logger.Printf("cloud: unreachable for 10 minutes (%v), sending directly to Telegram", err)
		}}, c
}
