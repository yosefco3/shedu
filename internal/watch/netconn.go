package watch

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"strconv"
	"strings"
)

// TCP states as written in /proc/net/tcp.
const (
	TCPEstablished = "01"
	TCPTimeWait    = "06"
	TCPListen      = "0A"
)

// Conn is one row of /proc/net/tcp or tcp6.
type Conn struct {
	LocalIP, RemoteIP     net.IP
	LocalPort, RemotePort uint16
	State                 string // hex code, e.g. "01"
	Inode                 uint64 // 0 once the owning process let go (TIME_WAIT)
}

// ParseProcNetTCP parses every row of /proc/net/tcp{,6}. Addresses are hex,
// each 32-bit word little-endian.
func ParseProcNetTCP(r io.Reader) ([]Conn, error) {
	var out []Conn
	sc := bufio.NewScanner(r)
	for first := true; sc.Scan(); first = false {
		if first {
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, err := parseHexEndpoint(f[1])
		if err != nil {
			return nil, err
		}
		rip, rport, err := parseHexEndpoint(f[2])
		if err != nil {
			return nil, err
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Conn{LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport, State: f[3], Inode: inode})
	}
	return out, sc.Err()
}

func parseHexEndpoint(s string) (net.IP, uint16, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad endpoint %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
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
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // ::ffff:a.b.c.d → a.b.c.d
	}
	return ip, uint16(port), nil
}

// ReadConns reads net/tcp and net/tcp6 under a /proc root. A missing tcp6
// (IPv6 disabled) is not an error.
func ReadConns(root fs.FS) ([]Conn, error) {
	var all []Conn
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		b, err := fs.ReadFile(root, name)
		if err != nil {
			if name == "net/tcp6" {
				continue
			}
			return nil, err
		}
		cs, err := ParseProcNetTCP(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		all = append(all, cs...)
	}
	return all, nil
}

// SocketOwners maps socket inodes to the pid holding them, by reading every
// /proc/<pid>/fd link. Without root only our own processes are visible.
func SocketOwners(root fs.FS) map[uint64]int {
	owners := map[uint64]int{}
	lr, ok := root.(linkReader)
	if !ok {
		return owners
	}
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return owners
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := fs.ReadDir(root, path.Join(e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := lr.ReadLink(path.Join(e.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			if s, ok := strings.CutPrefix(link, "socket:["); ok {
				if ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64); err == nil {
					owners[ino] = pid
				}
			}
		}
	}
	return owners
}

// Outgoing keeps the connections this host opened to another host: not
// listening, not loopback, and not someone connecting in to one of our ports.
// TIME_WAIT rows are kept: they are the trace of a connection that already
// closed, which is how short beacons show up between two polls.
func Outgoing(conns []Conn) []Conn {
	listening := map[uint16]bool{}
	for _, c := range conns {
		if c.State == TCPListen {
			listening[c.LocalPort] = true
		}
	}
	var out []Conn
	for _, c := range conns {
		if c.State != TCPEstablished && c.State != TCPTimeWait {
			continue
		}
		if c.RemoteIP.IsLoopback() || c.RemoteIP.IsUnspecified() || listening[c.LocalPort] {
			continue
		}
		out = append(out, c)
	}
	return out
}
