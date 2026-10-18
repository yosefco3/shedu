package watch

import (
	"fmt"
	"strconv"
)

// poolPorts are stratum ports used by public mining pools. Maintained here,
// not configurable, never downloaded.
var poolPorts = map[uint16]bool{
	3333: true, 3334: true, 3357: true, 4444: true, 5555: true, 6666: true, 7777: true, 9999: true,
	10128: true, 10343: true, 13333: true, 14433: true, 14444: true, 15555: true, 17777: true,
	19999: true, 20580: true, 45560: true, 45700: true,
}

// minerNames are process names of common miners and the malware that drops them
// (comm is cut at 15 characters).
var minerNames = map[string]bool{
	"xmrig": true, "xmr-stak": true, "minerd": true, "cpuminer": true, "ccminer": true,
	"kdevtmpfsi": true, "kinsing": true, "lolminer": true, "nbminer": true, "t-rex": true,
}

// minerHotSamples is how many consecutive samples above the CPU threshold
// count as "sustained" (two 30-second samples = a minute).
const minerHotSamples = 2

// MinerSignal decides whether a process that already burns CPU looks like a
// miner. High CPU alone (a build, a backup) is never enough: it needs a
// suspicious binary, a miner's name, or a connection to a pool port.
// poolDest is "ip:port" of such a connection, or "".
func MinerSignal(p Process, poolDest string) string {
	switch {
	case poolDest != "":
		return "pool"
	case minerNames[p.Comm]:
		return "name"
	case SuspiciousExec(p) != "":
		return "exe"
	}
	return ""
}

// poolConnsByPID maps pids to their first outgoing connection on a pool port.
func poolConnsByPID(conns []Conn, owners map[uint64]int) map[int]string {
	out := map[int]string{}
	for _, c := range Outgoing(conns) {
		if !poolPorts[c.RemotePort] {
			continue
		}
		if pid, ok := owners[c.Inode]; ok && c.Inode != 0 {
			if _, seen := out[pid]; !seen {
				out[pid] = fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)
			}
		}
	}
	return out
}

func cpuString(pct float64) string { return strconv.Itoa(int(pct + 0.5)) }
