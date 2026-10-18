package checks

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/watch"
)

// Secrets looks for credentials left where they leak: in a folder the web
// server serves, in a private key others can read, or in shell history.
// Findings name files only; a secret's content never leaves the server.
type Secrets struct {
	FS     fs.FS // the host's /
	IsRoot bool
}

// NewSecrets returns the production collector.
func NewSecrets() *Secrets { return &Secrets{FS: os.DirFS("/"), IsRoot: os.Geteuid() == 0} }

func (s *Secrets) Name() string { return "secrets" }

const (
	secretsMaxFiles = 50_000
	secretsMaxDepth = 6
	maxListed       = 5
)

var (
	backupExt  = []string{".sql", ".sql.gz", ".dump", ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".bak", ".old", ".swp"}
	skipDirs   = map[string]bool{"node_modules": true, "vendor": true, ".cache": true}
	reHistory  = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\w*\s*[=:]\s*\S{4,}|mysql\s.*\s-p\S{3,}|sshpass\s+-p\s*\S+|curl\s.*-u\s*\S+:\S+`)
	privateKey = []byte("PRIVATE KEY-----")
)

func (s *Secrets) Run(ctx context.Context) ([]finding.Finding, error) {
	var env, backups, gitDirs, keys, history []string

	for _, root := range watch.WebRoots {
		s.walkWeb(root, &env, &backups, &gitDirs, &keys)
	}
	for _, home := range homes(s.FS) {
		s.scanHome(home, &keys, &history)
	}

	var out []finding.Finding
	add := func(id string, sev finding.Severity, paths []string, fix func([]string) string) {
		if len(paths) == 0 {
			return
		}
		sort.Strings(paths)
		out = append(out, finding.Finding{ID: id, Severity: sev, Fix: fix(paths),
			Args:     map[string]string{"count": strconv.Itoa(len(paths)), "paths": listPaths(paths)},
			Evidence: strings.Join(paths, "\n")})
	}
	add("secrets.env_exposed", finding.High, env, func(p []string) string {
		return "curl -s -o /dev/null -w '%{http_code}\\n' http://localhost/.env   # 200 = anyone can download it"
	})
	add("secrets.git_exposed", finding.Medium, gitDirs, func(p []string) string {
		return "curl -s -o /dev/null -w '%{http_code}\\n' http://localhost/.git/HEAD   # 200 = your source code is public"
	})
	add("secrets.webroot_backup", finding.Medium, backups, func(p []string) string {
		return "sudo mkdir -p /root/web-backups && sudo mv " + strings.Join(head(p), " ") + " /root/web-backups/"
	})
	add("secrets.key_open", finding.High, keys, func(p []string) string {
		return "sudo chmod 600 " + strings.Join(head(p), " ")
	})
	add("secrets.history", finding.Medium, history, func(p []string) string {
		return "sudo truncate -s 0 " + strings.Join(head(p), " ") + "   # then change those passwords and tokens"
	})
	if !s.IsRoot {
		out = append(out, finding.Finding{ID: "secrets.need_root", Severity: finding.Info})
	}
	return out, nil
}

// walkWeb scans one web root. A folder with an index file is one the web
// server serves, so a .env or .git right there is downloadable.
func (s *Secrets) walkWeb(root string, env, backups, gitDirs, keys *[]string) {
	seen := 0
	_ = fs.WalkDir(s.FS, root, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		base := d.Name()
		if d.IsDir() {
			if base == ".git" {
				if servedDir(s.FS, path.Dir(name)) {
					*gitDirs = append(*gitDirs, "/"+name)
				}
				return fs.SkipDir
			}
			if skipDirs[base] || strings.Count(strings.TrimPrefix(name, root), "/") >= secretsMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if seen++; seen > secretsMaxFiles {
			return fs.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		lower := strings.ToLower(base)
		switch {
		case lower == ".env" || strings.HasPrefix(lower, ".env.") || strings.HasSuffix(lower, ".env"):
			if servedDir(s.FS, path.Dir(name)) {
				*env = append(*env, "/"+name)
			}
		case hasSuffix(lower, backupExt):
			*backups = append(*backups, "/"+name)
		case strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") || strings.HasPrefix(lower, "id_"):
			if isPrivateKey(s.FS, name) { // any private key in a web folder is one download away
				*keys = append(*keys, "/"+name)
			}
		}
		return nil
	})
}

// scanHome checks ~/.ssh private keys and shell history of one home (relative path).
func (s *Secrets) scanHome(home string, keys, history *[]string) {
	entries, _ := fs.ReadDir(s.FS, path.Join(home, ".ssh"))
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, ".pub") || n == "authorized_keys" || n == "known_hosts" || n == "config" {
			continue
		}
		p := path.Join(home, ".ssh", n)
		info, err := fs.Stat(s.FS, p)
		if err != nil || info.Mode().Perm()&0o077 == 0 {
			continue
		}
		if isPrivateKey(s.FS, p) {
			*keys = append(*keys, "/"+p)
		}
	}
	for _, h := range []string{".bash_history", ".zsh_history", ".mysql_history", ".psql_history"} {
		p := path.Join(home, h)
		if b, err := fs.ReadFile(s.FS, p); err == nil && historyHasSecret(b) {
			*history = append(*history, "/"+p)
		}
	}
}

// historyHasSecret reports whether a shell history holds a typed credential.
func historyHasSecret(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if reHistory.MatchString(sc.Text()) {
			return true
		}
	}
	return false
}

// servedDir reports whether dir (relative) looks like a document root.
func servedDir(fsys fs.FS, dir string) bool {
	for _, idx := range []string{"index.html", "index.htm", "index.php"} {
		if _, err := fs.Stat(fsys, path.Join(dir, idx)); err == nil {
			return true
		}
	}
	return false
}

func isPrivateKey(fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	return bytes.Contains(buf[:n], privateKey)
}

// homes returns the home folders (relative to fsys) of every account with
// one: /root plus anything under /home listed in passwd.
func homes(fsys fs.FS) []string {
	seen := map[string]bool{"root": true}
	out := []string{"root"}
	b, _ := fs.ReadFile(fsys, "etc/passwd")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		h := strings.TrimPrefix(path.Clean(f[5]), "/")
		if h == "" || h == "." || seen[h] || !strings.HasPrefix(h, "home/") {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func hasSuffix(s string, suffixes []string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func head(paths []string) []string {
	if len(paths) > maxListed {
		return paths[:maxListed]
	}
	return paths
}

func listPaths(paths []string) string {
	s := strings.Join(head(paths), ", ")
	if len(paths) > maxListed {
		s += ", …"
	}
	return s
}
