package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/cloud"
	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// runEnroll implements `shedu enroll <token> [--config PATH] [--url URL]` and
// `shedu enroll --off`. It writes CLOUD_URL and CLOUD_KEY to the config and asks the
// owner to restart the service; it never runs systemctl itself.
func runEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath, "path to the config file")
	url := fs.String("url", "", "cloud API URL (default "+config.DefaultCloudURL+")")
	off := fs.Bool("off", false, "disconnect: remove CLOUD_URL and CLOUD_KEY from the config")
	// accept the token before or after the flags
	var token string
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		token, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if token == "" && fs.NArg() > 0 {
		token = fs.Arg(0)
	}
	if *off {
		return enrollOff(*cfgPath)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "usage: shedu enroll <token> [--url URL] [--config PATH] | shedu enroll --off")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shedu:", err)
		return 1
	}
	base := cfg.CloudURL
	if *url != "" {
		base = *url
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := &cloud.Client{BaseURL: base, Version: version}
	resp, err := c.Enroll(ctx, cloudapi.EnrollRequest{
		Token: token, Hostname: cfg.Hostname, OS: osName(), Arch: runtime.GOARCH, AgentVersion: version,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "shedu: enroll failed:", err)
		return 1
	}
	store := base
	if strings.HasPrefix(resp.URL, "https://") {
		store = resp.URL // the cloud's canonical API address
	}
	if err := config.SetKeys(*cfgPath, map[string]string{"CLOUD_URL": strings.TrimRight(store, "/"), "CLOUD_KEY": resp.Key}); err != nil {
		fmt.Fprintln(os.Stderr, "shedu: enrolled, but could not save the key:", err)
		return 1
	}
	fmt.Printf("✔ enrolled as %s (id %s). Restart the service: sudo systemctl restart shedu\n", cfg.Hostname, resp.ServerID)
	return 0
}

// osName returns PRETTY_NAME from /etc/os-release, or "linux".
func osName() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "linux"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return "linux"
}

// enrollOff disconnects the server: first it tells the cloud (best effort, 5 seconds, so
// the dashboard shows "disconnected by the admin" instead of "not reporting"), then it
// removes CLOUD_URL and CLOUD_KEY. An unreachable cloud never blocks the local disconnect.
func enrollOff(cfgPath string) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shedu:", err)
		return 1
	}
	if cfg.CloudEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c := &cloud.Client{BaseURL: cfg.CloudURL, Key: cfg.CloudKey, Version: version}
		if err := c.Disconnect(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "shedu: could not tell the cloud (it will show the server as not reporting):", err)
		} else {
			fmt.Println("✔ the cloud was told; the dashboard shows this server as disconnected")
		}
		cancel()
	}
	if err := config.SetKeys(cfgPath, map[string]string{"CLOUD_URL": "", "CLOUD_KEY": ""}); err != nil {
		fmt.Fprintln(os.Stderr, "shedu:", err)
		return 1
	}
	fmt.Println("✔ cloud: off. Restart the service: sudo systemctl restart shedu")
	return 0
}
