package sysparse

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// OSRelease represents parsed /etc/os-release fields.
type OSRelease struct {
	ID         string
	Name       string
	Version    string
	VersionID  string
	PrettyName string
}

// ParseOSRelease parses /etc/os-release or a compatible file.
func ParseOSRelease(path string) (*OSRelease, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sysparse: open %s: %w", path, err)
	}
	defer f.Close()

	rel := &OSRelease{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.Trim(parts[1], "\"")

		switch key {
		case "ID":
			rel.ID = val
		case "NAME":
			rel.Name = val
		case "VERSION":
			rel.Version = val
		case "VERSION_ID":
			rel.VersionID = val
		case "PRETTY_NAME":
			rel.PrettyName = val
		}
	}
	return rel, scanner.Err()
}

// CrontabEntry represents a single crontab line.
type CrontabEntry struct {
	Minute  string
	Hour    string
	Day     string
	Month   string
	Weekday string
	User    string // only present in system crontab format
	Command string
	Raw     string
}

// ParseCrontab parses a crontab file. If systemFormat is true, expects a User field.
func ParseCrontab(path string, systemFormat bool) ([]CrontabEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("sysparse: open %s: %w", path, err)
	}
	defer f.Close()

	var entries []CrontabEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip variable assignments
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "@") {
			parts := strings.SplitN(line, "=", 2)
			if !strings.ContainsAny(parts[0], " \t") {
				continue
			}
		}

		entry, err := parseCrontabLine(line, systemFormat)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

func parseCrontabLine(line string, systemFormat bool) (CrontabEntry, error) {
	entry := CrontabEntry{Raw: line}

	// Handle @reboot, @daily, etc.
	if strings.HasPrefix(line, "@") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return entry, fmt.Errorf("malformed special cron line")
		}
		entry.Minute = fields[0] // @reboot, @daily, etc.
		if systemFormat && len(fields) >= 3 {
			entry.User = fields[1]
			entry.Command = strings.Join(fields[2:], " ")
		} else {
			entry.Command = strings.Join(fields[1:], " ")
		}
		return entry, nil
	}

	fields := strings.Fields(line)
	minFields := 6 // min hour day month weekday command
	if systemFormat {
		minFields = 7 // min hour day month weekday user command
	}
	if len(fields) < minFields {
		return entry, fmt.Errorf("too few fields")
	}

	entry.Minute = fields[0]
	entry.Hour = fields[1]
	entry.Day = fields[2]
	entry.Month = fields[3]
	entry.Weekday = fields[4]

	if systemFormat {
		entry.User = fields[5]
		entry.Command = strings.Join(fields[6:], " ")
	} else {
		entry.Command = strings.Join(fields[5:], " ")
	}

	return entry, nil
}

// SystemdUnit represents key parsed fields from a systemd unit file.
type SystemdUnit struct {
	ExecStart    string
	ExecStartPre string
	ExecStop     string
	Environment  string
	User         string
	WantedBy     string
	Type         string
}

// ParseSystemdUnit parses a systemd unit file and extracts key fields.
func ParseSystemdUnit(path string) (*SystemdUnit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sysparse: open %s: %w", path, err)
	}
	defer f.Close()

	unit := &SystemdUnit{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "ExecStart":
			unit.ExecStart = val
		case "ExecStartPre":
			unit.ExecStartPre = val
		case "ExecStop":
			unit.ExecStop = val
		case "Environment":
			unit.Environment = val
		case "User":
			unit.User = val
		case "WantedBy":
			unit.WantedBy = val
		case "Type":
			unit.Type = val
		}
	}
	return unit, scanner.Err()
}
