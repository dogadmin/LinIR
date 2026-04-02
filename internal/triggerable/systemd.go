//go:build linux

package triggerable

// systemdUnitDirs is the standard systemd unit search path (priority order).
// Shared across autostarts, scheduled, and keepalive collectors.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}
