//go:build linux

package retained

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// collectLinuxAuthHistory gathers authentication events from wtmp, btmp,
// and auth.log/secure within the given time window.
func collectLinuxAuthHistory(window time.Duration) ([]model.AuthEvent, error) {
	cutoff := time.Now().Add(-window)
	var events []model.AuthEvent

	// 1. wtmp — successful logins/logouts
	if wtmpEvents, err := parseUtmpFile("/var/log/wtmp", cutoff); err == nil {
		events = append(events, wtmpEvents...)
	}

	// 2. btmp — failed logins
	if btmpEvents, err := parseUtmpFile("/var/log/btmp", cutoff); err == nil {
		for i := range btmpEvents {
			btmpEvents[i].Success = false
			btmpEvents[i].Type = "failed_login"
			btmpEvents[i].Source = "btmp"
		}
		events = append(events, btmpEvents...)
	}

	// 3. auth.log / secure — sudo, su, sshd events
	authLogPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}
	for _, path := range authLogPaths {
		if logEvents, err := parseAuthLog(path, cutoff); err == nil {
			events = append(events, logEvents...)
		}
	}

	if len(events) > MaxAuthEvents {
		events = events[len(events)-MaxAuthEvents:]
	}
	return events, nil
}

// ========== utmp/wtmp/btmp binary parser ==========

// utmpRecordSize is the fixed size of a utmp record on Linux (384 bytes).
const utmpRecordSize = 384

// utmp record type constants
const (
	utEmpty       = 0
	utRunLevel    = 1
	utBootTime    = 2
	utNewTime     = 3
	utOldTime     = 4
	utInitProcess = 5
	utLoginProc   = 6
	utUserProc    = 7
	utDeadProc    = 8
)

// utmpRecord represents the raw binary layout of a Linux utmp record.
type utmpRecord struct {
	Type    int16
	_       int16 // padding
	PID     int32
	Line    [32]byte
	ID      [4]byte
	User    [32]byte
	Host    [256]byte
	Exit    [4]byte // exit_status
	Session int32
	TvSec   int32
	TvUsec  int32
	AddrV6  [4]int32
	_       [20]byte // reserved
}

func parseUtmpFile(path string, cutoff time.Time) ([]model.AuthEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Validate file size alignment — misaligned files indicate a different
	// utmp struct layout (e.g., 64-bit time_t glibc or non-x86 architecture).
	if info.Size()%utmpRecordSize != 0 {
		return nil, fmt.Errorf("utmp file %s size %d is not aligned to record size %d, skipping", path, info.Size(), utmpRecordSize)
	}

	recordCount := info.Size() / utmpRecordSize
	var events []model.AuthEvent

	for i := int64(0); i < recordCount; i++ {
		var rec utmpRecord
		if err := binary.Read(f, binary.LittleEndian, &rec); err != nil {
			break
		}

		// Only care about user login/logout entries
		if rec.Type != utUserProc && rec.Type != utDeadProc && rec.Type != utBootTime {
			continue
		}

		t := time.Unix(int64(rec.TvSec), int64(rec.TvUsec)*1000)
		if t.Before(cutoff) {
			continue
		}

		user := cString(rec.User[:])
		host := cString(rec.Host[:])
		line := cString(rec.Line[:])

		event := model.AuthEvent{
			Time:     t,
			User:     user,
			Source:   "wtmp",
			Terminal: line,
			Success:  true,
		}

		switch rec.Type {
		case utUserProc:
			event.Type = "login"
			if host != "" {
				event.RemoteIP = host
			}
		case utDeadProc:
			event.Type = "logout"
		case utBootTime:
			event.Type = "boot"
			event.User = "system"
		}

		// Try to extract IP from addr_v6
		if event.RemoteIP == "" && rec.AddrV6[0] != 0 {
			event.RemoteIP = ipFromAddr(rec.AddrV6)
		}

		events = append(events, event)
	}

	return events, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ipFromAddr(addr [4]int32) string {
	// Check if it's IPv4 (only first element non-zero)
	if addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(addr[0]))
		return ip.String()
	}
	// IPv6
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(ip[i*4:], uint32(addr[i]))
	}
	return ip.String()
}

// ========== auth.log / secure parser ==========

var (
	reSu     = regexp.MustCompile(`(\w+\s+\d+\s+[\d:]+)\s+\S+\s+su(?:\[\d+\])?:\s+(?:\(to\s+(\S+)\))?\s*(?:Successful|session opened)\s.*for\s+user\s+(\S+)`)
	reSuFail = regexp.MustCompile(`(\w+\s+\d+\s+[\d:]+)\s+\S+\s+su(?:\[\d+\])?:\s+(?:FAILED|pam_authenticate).*`)
)

func parseAuthLog(path string, cutoff time.Time) ([]model.AuthEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []model.AuthEvent
	year := time.Now().Year()

	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// SSH accepted
		if m := ReSSHAccept.FindStringSubmatch(line); m != nil {
			t := ParseSyslogTime(m[1], year)
			if t.Before(cutoff) {
				continue
			}
			events = append(events, model.AuthEvent{
				Time:     t,
				Type:     "ssh_accept",
				User:     m[2],
				RemoteIP: m[3],
				Source:   "auth.log",
				Success:  true,
			})
			continue
		}

		// SSH failed
		if m := ReSSHFail.FindStringSubmatch(line); m != nil {
			t := ParseSyslogTime(m[1], year)
			if t.Before(cutoff) {
				continue
			}
			events = append(events, model.AuthEvent{
				Time:     t,
				Type:     "ssh_reject",
				User:     m[2],
				RemoteIP: m[3],
				Source:   "auth.log",
				Success:  false,
			})
			continue
		}

		// sudo
		if m := ReSudo.FindStringSubmatch(line); m != nil {
			t := ParseSyslogTime(m[1], year)
			if t.Before(cutoff) {
				continue
			}
			events = append(events, model.AuthEvent{
				Time:    t,
				Type:    "sudo",
				User:    m[2],
				Source:  "auth.log",
				Success: true,
				Details: map[string]string{"command": m[3]},
			})
			continue
		}

		// su success
		if m := reSu.FindStringSubmatch(line); m != nil {
			t := ParseSyslogTime(m[1], year)
			if t.Before(cutoff) {
				continue
			}
			targetUser := m[2]
			if targetUser == "" {
				targetUser = m[3]
			}
			events = append(events, model.AuthEvent{
				Time:    t,
				Type:    "su",
				User:    targetUser,
				Source:  "auth.log",
				Success: true,
			})
			continue
		}

		// su failure
		if m := reSuFail.FindStringSubmatch(line); m != nil {
			t := ParseSyslogTime(m[1], year)
			if t.Before(cutoff) {
				continue
			}
			events = append(events, model.AuthEvent{
				Time:    t,
				Type:    "su",
				Source:  "auth.log",
				Success: false,
			})
		}
	}

	return events, nil
}

// collectLinuxLogEvents extracts time-windowed log entries from syslog/journal files.
func collectLinuxLogEvents(window time.Duration) ([]model.LogEvent, error) {
	cutoff := time.Now().Add(-window)
	var events []model.LogEvent

	logPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
	}

	year := time.Now().Year()

	for _, path := range logPaths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if len(line) < 16 {
				continue
			}

			// Parse timestamp
			timeStr := line[:15]
			t := ParseSyslogTime(timeStr, year)
			if t.IsZero() || t.Before(cutoff) {
				continue
			}

			// Extract process name and message
			rest := line[16:]
			process := ""
			message := rest
			if idx := strings.Index(rest, ": "); idx > 0 {
				header := rest[:idx]
				message = rest[idx+2:]
				// Extract process name from "hostname process[pid]"
				parts := strings.Fields(header)
				if len(parts) >= 2 {
					proc := parts[len(parts)-1]
					if bracketIdx := strings.Index(proc, "["); bracketIdx > 0 {
						proc = proc[:bracketIdx]
					}
					process = proc
				}
			}

			// Filter: only include potentially interesting entries
			linuxExtra := []string{"polkitd", "chpasswd", "groupadd", "gdm", "lightdm",
				"iptables", "nftables", "apparmor", "selinux"}
			if !IsInterestingLogProcess(process, message, linuxExtra) {
				continue
			}

			severity := ClassifyLogSeverity(message)

			events = append(events, model.LogEvent{
				Time:     t,
				Process:  process,
				Message:  message,
				Source:   fmt.Sprintf("syslog:%s", path),
				Severity: severity,
			})
		}
		f.Close()
	}

	if len(events) > MaxAuthEvents {
		events = events[len(events)-MaxAuthEvents:]
	}
	return events, nil
}
