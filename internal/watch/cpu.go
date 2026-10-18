package watch

import "time"

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat times. It is 100 on
// every mainstream Linux build; reading it properly needs sysconf (cgo).
const clockTicks = 100

// CPUPercent is the share of one core cur used since prev, wall time apart:
// 100 means one core fully busy, 400 four cores. A different process
// instance (pid reused) or a clock going backwards gives 0.
func CPUPercent(prev, cur Process, wall time.Duration) float64 {
	if wall <= 0 || prev.PID != cur.PID || prev.StartTicks != cur.StartTicks || cur.CPUTicks < prev.CPUTicks {
		return 0
	}
	used := float64(cur.CPUTicks-prev.CPUTicks) / clockTicks
	return used / wall.Seconds() * 100
}
