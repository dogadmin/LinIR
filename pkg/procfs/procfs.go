//go:build linux

package procfs

import (
	"fmt"
	"os"
	"strconv"
)

// ProcRoot is the root of the proc filesystem. Override for testing.
var ProcRoot = "/proc"

// ListPIDs returns all numeric PID directories under /proc.
func ListPIDs() ([]int, error) {
	entries, err := os.ReadDir(ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("procfs: readdir %s: %w", ProcRoot, err)
	}

	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// ReadFileString reads the contents of a file as a string.
// Returns empty string and nil error if the file doesn't exist (process exited).
func ReadFileString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// ReadLink reads a symlink target. Returns empty string if not readable.
func ReadLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}
