//go:build linux

package retained

import (
	"os"
	"strconv"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/procfs"
)

// detectMapsArtifacts finds process memory maps pointing to files that no longer
// exist on disk. This is Linux-specific (/proc/<pid>/maps).
// Filters out standard library paths that commonly disappear during package upgrades.
func detectMapsArtifacts(procs []model.ProcessInfo) []model.ArtifactFinding {
	var findings []model.ArtifactFinding
	seen := make(map[string]struct{})

	for _, p := range procs {
		maps, err := procfs.ReadMapsSummary(p.PID)
		if err != nil || len(maps) == 0 {
			continue
		}
		for _, path := range maps {
			if _, ok := seen[path]; ok {
				continue
			}
			if _, err := os.Stat(path); err == nil {
				continue // file exists
			}
			seen[path] = struct{}{}

			// Skip standard library paths — these commonly disappear during
			// package upgrades (old .so version removed, process still maps it)
			if isStandardLibPath(path) {
				continue
			}

			findings = append(findings, model.ArtifactFinding{
				Type:       "maps_missing",
				Path:       path,
				LinkedPID:  p.PID,
				Reason:     "进程内存映射指向已不存在的文件",
				Source:     "procfs",
				Confidence: "medium",
				Details: map[string]string{
					"pid":  strconv.Itoa(p.PID),
					"name": p.Name,
				},
			})
		}
	}

	return findings
}

func isStandardLibPath(path string) bool {
	stdPrefixes := []string{
		"/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
		"/usr/libexec/", "/usr/share/",
	}
	for _, prefix := range stdPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
