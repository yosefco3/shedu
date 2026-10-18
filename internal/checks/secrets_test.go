package checks

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yosefco3/shedu/internal/i18n"
)

const fakeKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"

func secretsFixture() fstest.MapFS {
	return fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")},
		// a served folder (has index.php) with a .env and a .git
		"var/www/html/index.php":   {Data: []byte("<?php")},
		"var/www/html/.env":        {Data: []byte("AWS_SECRET=abcd1234\n"), Mode: 0o644},
		"var/www/html/.git/HEAD":   {Data: []byte("ref: refs/heads/main\n")},
		"var/www/html/db-2026.sql": {Data: []byte("INSERT ...")},
		// Laravel layout: .env next to public/, not served
		"var/www/app/.env":                    {Data: []byte("DB_PASSWORD=x\n")},
		"var/www/app/public/index.php":        {Data: []byte("<?php")},
		"var/www/app/node_modules/x/.env.zip": {Data: []byte("ignored")},
		// keys
		"home/bob/.ssh/id_ed25519":     {Data: []byte(fakeKey), Mode: 0o644},
		"home/bob/.ssh/id_ed25519.pub": {Data: []byte("ssh-ed25519 AAAA bob"), Mode: 0o644},
		"root/.ssh/id_rsa":             {Data: []byte(fakeKey), Mode: 0o600},
		"var/www/html/certs/site.pem":  {Data: []byte("-----BEGIN CERTIFICATE-----\n")},
		// history
		"home/bob/.bash_history": {Data: []byte("ls\nexport API_KEY=sk-live-123456\nmysql -u root -pS3cret db\n")},
		"root/.bash_history":     {Data: []byte("apt update\nsudo systemctl restart nginx\n")},
	}
}

func TestSecrets(t *testing.T) {
	s := &Secrets{FS: secretsFixture(), IsRoot: true}
	fs, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.ID] = f.Args["paths"]
	}
	want := map[string]string{
		"secrets.env_exposed":    "/var/www/html/.env",
		"secrets.git_exposed":    "/var/www/html/.git",
		"secrets.webroot_backup": "/var/www/html/db-2026.sql",
		"secrets.key_open":       "/home/bob/.ssh/id_ed25519",
		"secrets.history":        "/home/bob/.bash_history",
	}
	if len(got) != len(want) {
		t.Errorf("findings: %v", got)
	}
	for id, p := range want {
		if got[id] != p {
			t.Errorf("%s = %q, want %q", id, got[id], p)
		}
	}
	// the secret itself never reaches a message
	for _, f := range fs {
		for _, lang := range []i18n.Lang{i18n.En, i18n.He} {
			m := i18n.Render(lang, f.ID, f.Args)
			if text := m.Title + m.Explain + f.Fix + f.Evidence; strings.Contains(text, "abcd1234") || strings.Contains(text, "S3cret") || strings.Contains(text, "sk-live") {
				t.Errorf("%s leaks a secret: %s", f.ID, text)
			}
		}
	}
	for _, f := range fs {
		if f.ID == "secrets.key_open" && f.Fix != "sudo chmod 600 /home/bob/.ssh/id_ed25519" {
			t.Errorf("fix: %q", f.Fix)
		}
	}
}

func TestSecretsClean(t *testing.T) {
	clean := fstest.MapFS{
		"etc/passwd":               {Data: []byte("bob:x:1000:1000::/home/bob:/bin/bash\n")},
		"var/www/html/index.php":   {Data: []byte("<?php")},
		"home/bob/.ssh/id_ed25519": {Data: []byte(fakeKey), Mode: 0o600},
		"home/bob/.bash_history":   {Data: []byte("git status\npasswd\n")},
	}
	if fs, _ := (&Secrets{FS: clean, IsRoot: true}).Run(context.Background()); len(fs) != 0 {
		t.Errorf("clean host: %+v", fs)
	}
	if fs, _ := (&Secrets{FS: clean}).Run(context.Background()); len(fs) != 1 || fs[0].ID != "secrets.need_root" {
		t.Errorf("non-root: %+v", fs)
	}
}

func TestHistoryPatterns(t *testing.T) {
	yes := []string{"export DB_PASSWORD=hunter22", "curl -u admin:pa55word https://x", "mysql -uroot -pTopSecret", "TOKEN: abcdef12", "sshpass -p hunter2 ssh x"}
	no := []string{"passwd", "echo $PASSWORD", "git commit -m 'fix token refresh'", "ls -p"}
	for _, l := range yes {
		if !historyHasSecret([]byte(l)) {
			t.Errorf("missed: %s", l)
		}
	}
	for _, l := range no {
		if historyHasSecret([]byte(l)) {
			t.Errorf("false positive: %s", l)
		}
	}
}
