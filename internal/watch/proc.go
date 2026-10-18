package watch

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Process is one running process as seen in /proc at a single moment.
type Process struct {
	PID        int
	PPID       int
	UID        int      // real uid, from status
	Exe        string   // readlink exe, without " (deleted)"; "" for kernel threads or no permission
	ExeDeleted bool     // the binary was removed from disk while running
	Cwd        string   // readlink cwd
	Cmdline    []string // NUL-separated argv
	Comm       string   // short name from comm
	StartTicks uint64   // field 22 of stat: clock ticks since boot
}

// linkReader is implemented by the /proc roots we use. Go 1.22 has no
// fs.ReadLinkFS, so we carry our own.
type linkReader interface {
	ReadLink(name string) (string, error)
}

const deletedSuffix = " (deleted)"

// ReadProcess parses one /proc/<pid> directory under root. stat is required;
// exe and cwd are best-effort, since kernel threads and some processes refuse them.
func ReadProcess(root fs.FS, pid int) (Process, error) {
	dir := strconv.Itoa(pid)
	p := Process{PID: pid}

	stat, err := fs.ReadFile(root, path.Join(dir, "stat"))
	if err != nil {
		return Process{}, err
	}
	if err := parseStat(stat, &p); err != nil {
		return Process{}, fmt.Errorf("pid %d: %w", pid, err)
	}
	if b, err := fs.ReadFile(root, path.Join(dir, "status")); err == nil {
		p.UID = parseStatusUID(b)
	} else {
		p.UID = -1
	}
	if b, err := fs.ReadFile(root, path.Join(dir, "comm")); err == nil {
		p.Comm = strings.TrimRight(string(b), "\n")
	}
	if b, err := fs.ReadFile(root, path.Join(dir, "cmdline")); err == nil {
		b = bytes.TrimRight(b, "\x00")
		if len(b) > 0 {
			p.Cmdline = strings.Split(string(b), "\x00")
		}
	}
	if lr, ok := root.(linkReader); ok {
		if exe, err := lr.ReadLink(path.Join(dir, "exe")); err == nil {
			p.Exe, p.ExeDeleted = strings.CutSuffix(exe, deletedSuffix)
		}
		if cwd, err := lr.ReadLink(path.Join(dir, "cwd")); err == nil {
			p.Cwd = cwd
		}
	}
	return p, nil
}

// parseStat reads ppid (field 4) and starttime (field 22). comm (field 2)
// may contain spaces and parentheses, so fields are counted after the last ')'.
func parseStat(b []byte, p *Process) error {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return errors.New("stat: no comm")
	}
	f := strings.Fields(string(b[i+1:])) // f[0] is field 3 (state)
	if len(f) < 20 {
		return errors.New("stat: too few fields")
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return fmt.Errorf("stat ppid: %w", err)
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return fmt.Errorf("stat starttime: %w", err)
	}
	p.PPID, p.StartTicks = ppid, start
	return nil
}

// parseStatusUID returns the real uid from the "Uid:" line, or -1.
func parseStatusUID(b []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				if uid, err := strconv.Atoi(f[0]); err == nil {
					return uid
				}
			}
		}
	}
	return -1
}

// Inventory reads every numeric entry under root, sorted by PID. A process
// that exits mid-scan is skipped, not an error.
func Inventory(root fs.FS) ([]Process, error) {
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, err
	}
	var out []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		p, err := ReadProcess(root, pid)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// procFS is a /proc-shaped directory on disk with readlink support.
type procFS struct {
	fs.FS
	dir string
}

func newProcFS(dir string) procFS { return procFS{os.DirFS(dir), dir} }

func (p procFS) ReadLink(name string) (string, error) { return os.Readlink(path.Join(p.dir, name)) }

// OSInventory snapshots the host's /proc.
func OSInventory() ([]Process, error) { return Inventory(newProcFS("/proc")) }
