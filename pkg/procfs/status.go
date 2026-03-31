//go:build linux

package procfs

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ProcStatus represents parsed /proc/[pid]/status key-value fields.
type ProcStatus struct {
	Name    string
	State   string
	TGID    int
	PID     int
	PPID    int
	UID     [4]int // Real, Effective, Saved, FS
	GID     [4]int
	Threads int
	VMPeak  uint64 // kB
	VMSize  uint64 // kB
	VMRSS   uint64 // kB
	NSpid   []int  // Namespace PIDs
}

// ReadStatus parses /proc/[pid]/status.
func ReadStatus(pid int) (*ProcStatus, error) {
	path := fmt.Sprintf("%s/%d/status", ProcRoot, pid)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	status := &ProcStatus{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			status.Name = val
		case "State":
			status.State = val
		case "Tgid":
			status.TGID, _ = strconv.Atoi(val)
		case "Pid":
			status.PID, _ = strconv.Atoi(val)
		case "PPid":
			status.PPID, _ = strconv.Atoi(val)
		case "Uid":
			parseIDs(val, status.UID[:])
		case "Gid":
			parseIDs(val, status.GID[:])
		case "Threads":
			status.Threads, _ = strconv.Atoi(val)
		case "VmPeak":
			status.VMPeak = parseKB(val)
		case "VmSize":
			status.VMSize = parseKB(val)
		case "VmRSS":
			status.VMRSS = parseKB(val)
		case "NSpid":
			for _, s := range strings.Fields(val) {
				if id, err := strconv.Atoi(s); err == nil {
					status.NSpid = append(status.NSpid, id)
				}
			}
		}
	}

	return status, scanner.Err()
}

func parseIDs(val string, ids []int) {
	fields := strings.Fields(val)
	for i := 0; i < len(fields) && i < len(ids); i++ {
		ids[i], _ = strconv.Atoi(fields[i])
	}
}

func parseKB(val string) uint64 {
	// Format: "12345 kB"
	val = strings.TrimSuffix(val, " kB")
	val = strings.TrimSpace(val)
	v, _ := strconv.ParseUint(val, 10, 64)
	return v
}
