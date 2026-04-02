//go:build darwin

package retained

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// collectDarwinAuthHistory gathers authentication events from macOS log files.
// Note: unified logs require `log show` command which we avoid. We parse
// available text log files directly.
func collectDarwinAuthHistory(window time.Duration) ([]model.AuthEvent, error) {
	cutoff := time.Now().Add(-window)
	var events []model.AuthEvent

	// SSH-related logs from /var/log/system.log
	logPaths := []string{
		"/var/log/system.log",
		"/private/var/log/system.log",
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
					Source:   "system.log",
					Success:  true,
				})
			} else if m := ReSSHFail.FindStringSubmatch(line); m != nil {
				t := ParseSyslogTime(m[1], year)
				if t.Before(cutoff) {
					continue
				}
				events = append(events, model.AuthEvent{
					Time:     t,
					Type:     "ssh_reject",
					User:     m[2],
					RemoteIP: m[3],
					Source:   "system.log",
					Success:  false,
				})
			} else if m := ReSudo.FindStringSubmatch(line); m != nil {
				t := ParseSyslogTime(m[1], year)
				if t.Before(cutoff) {
					continue
				}
				events = append(events, model.AuthEvent{
					Time:    t,
					Type:    "sudo",
					User:    m[2],
					Source:  "system.log",
					Success: true,
					Details: map[string]string{"command": m[3]},
				})
			}
		}
		f.Close()
	}

	if len(events) > MaxAuthEvents {
		events = events[len(events)-MaxAuthEvents:]
	}
	return events, nil
}

// collectDarwinLogEvents extracts time-windowed log entries from system.log.
func collectDarwinLogEvents(window time.Duration) ([]model.LogEvent, error) {
	cutoff := time.Now().Add(-window)
	var events []model.LogEvent
	year := time.Now().Year()

	logPaths := []string{
		"/var/log/system.log",
		"/private/var/log/system.log",
	}

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

			timeStr := line[:15]
			t := ParseSyslogTime(timeStr, year)
			if t.IsZero() || t.Before(cutoff) {
				continue
			}

			rest := line[16:]
			process := ""
			message := rest
			if idx := strings.Index(rest, ": "); idx > 0 {
				header := rest[:idx]
				message = rest[idx+2:]
				parts := strings.Fields(header)
				if len(parts) >= 2 {
					proc := parts[len(parts)-1]
					if bracketIdx := strings.Index(proc, "["); bracketIdx > 0 {
						proc = proc[:bracketIdx]
					}
					process = proc
				}
			}

			darwinExtra := []string{"launchd", "SecurityAgent", "authorizationhost",
				"sandboxd", "tccd", "xpcproxy"}
			if !IsInterestingLogProcess(process, message, darwinExtra) {
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

