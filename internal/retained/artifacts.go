package retained

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// detectArtifacts finds forensic residue from processes and persistence items.
func detectArtifacts(procs []model.ProcessInfo, persistence []model.PersistenceItem) []model.ArtifactFinding {
	var findings []model.ArtifactFinding

	// 1. Process-based artifacts: deleted exe
	findings = append(findings, detectProcessArtifacts(procs)...)

	// 2. Persistence target missing
	findings = append(findings, detectPersistenceTargetMissing(persistence)...)

	// 3. Orphaned executables in tmp dirs (not linked to running process)
	findings = append(findings, detectTmpExecutables(procs)...)

	return findings
}

func detectProcessArtifacts(procs []model.ProcessInfo) []model.ArtifactFinding {
	var findings []model.ArtifactFinding
	for _, p := range procs {
		for _, flag := range p.SuspiciousFlags {
			if flag == "exe_deleted" {
				findings = append(findings, model.ArtifactFinding{
					Type:       "deleted_exe",
					Path:       p.Exe,
					LinkedPID:  p.PID,
					Reason:     "进程可执行文件已被删除但进程仍在运行",
					Source:     "procfs",
					Confidence: "high",
					Details: map[string]string{
						"pid":  strconv.Itoa(p.PID),
						"name": p.Name,
						"exe":  p.Exe,
					},
				})
			}
		}
	}
	return findings
}

func detectPersistenceTargetMissing(persistence []model.PersistenceItem) []model.ArtifactFinding {
	var findings []model.ArtifactFinding
	seen := make(map[string]struct{})

	for _, item := range persistence {
		if item.Target == "" || item.Exists {
			continue
		}
		hasMissing := false
		for _, flag := range item.RiskFlags {
			if flag == "target_missing" {
				hasMissing = true
				break
			}
		}
		if !hasMissing {
			continue
		}
		if _, ok := seen[item.Target]; ok {
			continue
		}
		seen[item.Target] = struct{}{}

		findings = append(findings, model.ArtifactFinding{
			Type:       "persist_target_missing",
			Path:       item.Target,
			LinkedItem: item.Path,
			Reason:     "持久化配置指向不存在的目标文件",
			Source:     "filesystem",
			Confidence: "high",
			Details: map[string]string{
				"persistence_type": item.Type,
				"persistence_path": item.Path,
			},
		})
	}
	return findings
}

// detectTmpExecutables scans common temp directories for executable files
// not linked to any currently running process.
func detectTmpExecutables(procs []model.ProcessInfo) []model.ArtifactFinding {
	knownExes := make(map[string]struct{})
	for _, p := range procs {
		if p.Exe != "" {
			knownExes[p.Exe] = struct{}{}
		}
	}

	tmpDirs := []string{"/tmp", "/var/tmp", "/dev/shm", "/dev/mqueue", "/private/tmp"}
	// Known legitimate temp prefixes
	legitPrefixes := []string{
		"systemd-private-", "snap.", "flatpak-", "apt-dpkg-install-",
		"npm-", "yarn-", "pip-", "go-build", "nix-build-", "docker-", "containerd",
	}
	var findings []model.ArtifactFinding

	for _, dir := range tmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode().Perm()&0111 == 0 {
				continue
			}
			if _, ok := knownExes[path]; ok {
				continue
			}
			// Skip known legitimate temp file patterns
			isLegit := false
			for _, prefix := range legitPrefixes {
				if strings.HasPrefix(entry.Name(), prefix) {
					isLegit = true
					break
				}
			}
			if isLegit {
				continue
			}

			findings = append(findings, model.ArtifactFinding{
				Type:       "tmp_executable",
				Path:       path,
				Reason:     "临时目录中存在可执行文件（无关联运行进程）",
				Source:     "filesystem",
				Confidence: "medium",
				Details: map[string]string{
					"size": strconv.FormatInt(info.Size(), 10),
					"mode": info.Mode().String(),
				},
			})
		}
	}

	return findings
}
