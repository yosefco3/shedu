package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SetKeys rewrites path so that every key in kv has the given value, written as
// KEY="value". An empty value removes the key. Comments, blank lines and the order of the
// other lines are kept; new keys are appended. The write is atomic (temp file + rename)
// and the result is 0600, because the file holds secrets. A missing file is created.
//
// Besides install.sh, this is the only place the agent writes to /etc/shedu.
func SetKeys(path string, kv map[string]string) error {
	for k, v := range kv {
		if k == "" || strings.ContainsAny(k, "= \t\n#") {
			return fmt.Errorf("config: invalid key %q", k)
		}
		if strings.ContainsAny(v, "\"\n\r") {
			return fmt.Errorf("config: value of %s must not contain quotes or newlines", k)
		}
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	done := map[string]bool{}
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(old))
	for sc.Scan() {
		line := sc.Text()
		key, _, isKV := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if v, ours := kv[key]; isKV && ours && !strings.HasPrefix(key, "#") {
			if !done[key] && v != "" {
				fmt.Fprintf(&out, "%s=\"%s\"\n", key, v)
			}
			done[key] = true // a duplicate line of the same key is dropped
			continue
		}
		out.WriteString(line + "\n")
	}
	if err := sc.Err(); err != nil {
		return err
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !done[k] && kv[k] != "" {
			fmt.Fprintf(&out, "%s=\"%s\"\n", k, kv[k])
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".guard.conf.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
