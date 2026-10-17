package checks

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yosefco12/shedu/internal/finding"
)

// Listener is one TCP socket in LISTEN state.
type Listener struct {
	Proto   string // "tcp" or "tcp6"
	Addr    net.IP
	Port    int
	Inode   uint64
	PID     int    // 0 if unknown
	Process string // /proc/<pid>/comm, "" if unknown
}

// Ports lists listening TCP sockets straight from /proc, so it needs neither
// ss nor netstat, and flags internal services exposed to the world.
type Ports struct {
	Open    func(proto string) (io.ReadCloser, error) // /proc/net/tcp or /proc/net/tcp6
	Resolve func(inode uint64) (pid int, comm string) // socket inode → owning process
	HasUFW  bool                                      // decides the fix command
}

// NewPorts returns the production collector.
func NewPorts() *Ports {
	_, ufwErr := exec.LookPath("ufw")
	return &Ports{
		Open:    func(proto string) (io.ReadCloser, error) { return os.Open("/proc/net/" + proto) },
		Resolve: resolveInode(),
		HasUFW:  ufwErr == nil,
	}
}

func (p *Ports) Name() string { return "ports" }

type service struct {
	name string
	sev  finding.Severity
}

// internalServices should never listen on a public address. Critical ones
// commonly run without authentication by default.
var internalServices = map[int]service{
	6379:  {"redis", finding.Critical},
	27017: {"mongodb", finding.Critical},
	9200:  {"elasticsearch", finding.Critical},
	11211: {"memcached", finding.Critical},
	2375:  {"docker-api", finding.Critical},
	3306:  {"mysql", finding.High},
	5432:  {"postgresql", finding.High},
	5672:  {"rabbitmq", finding.High},
	9000:  {"php-fpm", finding.High},
}

var devPorts = map[int]bool{3000: true, 5000: true, 8000: true, 8080: true}

// Run reads both tables, resolves processes, and reports exposed services plus
// an always-present summary of what is reachable from outside.
func (p *Ports) Run(ctx context.Context) ([]finding.Finding, error) {
	var all []Listener
	for _, proto := range []string{"tcp", "tcp6"} {
		r, err := p.Open(proto)
		if err != nil {
			if os.IsNotExist(err) {
				continue // IPv6 disabled
			}
			return nil, fmt.Errorf("open /proc/net/%s: %w", proto, err)
		}
		ls, err := ParseProcNetTCP(r, proto)
		r.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, ls...)
	}
	for i := range all {
		if p.Resolve != nil {
			all[i].PID, all[i].Process = p.Resolve(all[i].Inode)
		}
	}
	return p.analyse(all), nil
}

func (p *Ports) analyse(ls []Listener) []finding.Finding {
	public := map[int]string{} // port → process (first seen)
	for _, l := range ls {
		if !IsPublic(l.Addr) {
			continue
		}
		if _, seen := public[l.Port]; !seen || public[l.Port] == "" {
			public[l.Port] = l.Process
		}
	}
	ports := make([]int, 0, len(public))
	for port := range public {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	var fs []finding.Finding
	var summary []string
	for _, port := range ports {
		proc := public[port]
		label := strconv.Itoa(port)
		if proc != "" {
			label += " " + proc
		}
		summary = append(summary, label)
		if svc, ok := internalServices[port]; ok {
			fs = append(fs, finding.Finding{
				ID: "ports.db_public", Severity: svc.sev, Fix: p.fix(port, proc),
				Args:     map[string]string{"port": strconv.Itoa(port), "service": svc.name, "process": proc},
				Evidence: fmt.Sprintf("tcp *:%d LISTEN (%s)", port, proc),
			})
		} else if devPorts[port] {
			fs = append(fs, finding.Finding{
				ID: "ports.dev_public", Severity: finding.Info,
				Args: map[string]string{"port": strconv.Itoa(port), "process": proc},
			})
		}
	}
	fs = append(fs, finding.Finding{
		ID: "ports.summary", Severity: finding.Info,
		Args: map[string]string{"count": strconv.Itoa(len(ports)), "list": strings.Join(summary, ", ")},
	})
	return fs
}

func (p *Ports) fix(port int, proc string) string {
	if proc == "" {
		proc = "the service"
	}
	if p.HasUFW {
		return fmt.Sprintf("sudo ufw deny %d/tcp   # better: bind %s to 127.0.0.1 in its config", port, proc)
	}
	return fmt.Sprintf("# bind %s to 127.0.0.1 in its config, or: sudo apt install -y ufw && sudo ufw allow OpenSSH && sudo ufw deny %d/tcp && sudo ufw --force enable", proc, port)
}

// IsPublic reports whether a listening address accepts connections from other hosts.
func IsPublic(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true // 0.0.0.0 or ::
	}
	return !ip.IsLoopback()
}

// ParseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6 and keeps LISTEN (0A) rows.
func ParseProcNetTCP(r io.Reader, proto string) ([]Listener, error) {
	var out []Listener
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false // header
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		addr, port, err := parseHexAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("/proc/net/%s: %w", proto, err)
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Listener{Proto: proto, Addr: addr, Port: port, Inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0CEA" (IPv4) or the 32-hex-digit IPv6 form.
// Each 32-bit word is stored little-endian on little-endian hosts.
func parseHexAddr(s string) (net.IP, int, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseInt(p, 16, 32)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port in %q", s)
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad ip in %q", s)
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return ip, int(port), nil
}

// resolveInode scans /proc/*/fd once and maps socket inodes to processes.
// Without root it only sees the current user's processes; unknown → (0, "").
func resolveInode() func(uint64) (int, string) {
	var table map[uint64]int
	return func(inode uint64) (int, string) {
		if table == nil {
			table = scanProcFDs()
		}
		pid, ok := table[inode]
		if !ok {
			return 0, ""
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		return pid, strings.TrimSpace(string(comm))
	}
}

func scanProcFDs() map[uint64]int {
	table := map[uint64]int{}
	procs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, dir := range procs {
		pid, _ := strconv.Atoi(strings.Split(dir, "/")[2])
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err == nil {
				table[ino] = pid
			}
		}
	}
	return table
}
