//go:build linux

package procfs

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// MapsEntry represents a single line from /proc/[pid]/maps.
type MapsEntry struct {
	AddressStart string
	AddressEnd   string
	Permissions  string // e.g., "r-xp"
	Offset       string
	Device       string
	Inode        uint64
	Pathname     string
}

// ReadMaps parses /proc/[pid]/maps and returns a summary of mapped files.
func ReadMaps(pid int) ([]MapsEntry, error) {
	path := fmt.Sprintf("%s/%d/maps", ProcRoot, pid)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []MapsEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseMapsLine(line)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// ReadMapsSummary returns deduplicated list of mapped file paths for a process.
func ReadMapsSummary(pid int) ([]string, error) {
	entries, err := ReadMaps(pid)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var paths []string
	for _, e := range entries {
		if e.Pathname == "" || strings.HasPrefix(e.Pathname, "[") {
			continue // skip anonymous and special mappings
		}
		if _, ok := seen[e.Pathname]; !ok {
			seen[e.Pathname] = struct{}{}
			paths = append(paths, e.Pathname)
		}
	}
	return paths, nil
}

func parseMapsLine(line string) (MapsEntry, error) {
	// Format: address perms offset dev inode pathname
	// Example: 7f1234000000-7f1234001000 r-xp 00000000 08:01 12345 /usr/lib/libc.so.6
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return MapsEntry{}, fmt.Errorf("too few fields")
	}

	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return MapsEntry{}, fmt.Errorf("invalid address range")
	}

	entry := MapsEntry{
		AddressStart: addrParts[0],
		AddressEnd:   addrParts[1],
		Permissions:  fields[1],
		Offset:       fields[2],
		Device:       fields[3],
	}
	fmt.Sscanf(fields[4], "%d", &entry.Inode)

	if len(fields) >= 6 {
		entry.Pathname = strings.Join(fields[5:], " ")
	}

	return entry, nil
}
