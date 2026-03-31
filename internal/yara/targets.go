package yara

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// CollectHighRiskTargets 根据采集结果自动选择高风险扫描目标。
//
// 扫描策略（按设计文档第十三节）：
//   1. 当前联网进程对应的可执行文件
//   2. 持久化项引用的目标文件
//   3. 临时目录中的可执行/脚本
//   4. 用户目录中的伪装文件
//   5. /tmp, /var/tmp, /dev/shm
//   6. LaunchAgents/systemd/cron 引用的脚本或二进制
func CollectHighRiskTargets(result *model.CollectionResult) []ScanTarget {
	seen := make(map[string]struct{})
	var targets []ScanTarget

	add := func(path, targetType string, linkedPID int) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		// 检查文件是否存在且可读
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return
		}
		seen[path] = struct{}{}
		targets = append(targets, ScanTarget{
			Path:       path,
			TargetType: targetType,
			LinkedPID:  linkedPID,
		})
	}

	// 1. 联网进程的可执行文件
	networkedPIDs := make(map[int]struct{})
	for _, c := range result.Connections {
		if c.PID > 0 && (c.State == "ESTABLISHED" || c.State == "LISTEN") {
			networkedPIDs[c.PID] = struct{}{}
		}
	}
	for _, p := range result.Processes {
		if _, isNetworked := networkedPIDs[p.PID]; isNetworked {
			add(p.Exe, "process-linked-file", p.PID)
		}
	}

	// 2. 可疑进程的可执行文件（有 SuspiciousFlags 的）
	for _, p := range result.Processes {
		if len(p.SuspiciousFlags) > 0 && p.Exe != "" {
			add(p.Exe, "process-linked-file", p.PID)
		}
	}

	// 3. 持久化项引用的目标文件
	for _, item := range result.Persistence {
		if item.Target != "" {
			add(item.Target, "persistence-target", 0)
		}
	}

	// 4. 临时目录扫描
	tmpDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	for _, dir := range tmpDirs {
		scanDirForExecutables(dir, &targets, seen, 2) // 最多递归 2 层
	}

	return targets
}

// ScanTarget 表示一个待扫描目标
type ScanTarget struct {
	Path       string
	TargetType string // "file", "process-linked-file", "persistence-target"
	LinkedPID  int
}

// scanDirForExecutables 扫描目录中的可执行文件和脚本
func scanDirForExecutables(dir string, targets *[]ScanTarget, seen map[string]struct{}, maxDepth int) {
	if maxDepth < 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			scanDirForExecutables(path, targets, seen, maxDepth-1)
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		// 可执行文件或脚本
		if info.Mode().Perm()&0111 != 0 || isScriptExtension(entry.Name()) {
			if _, ok := seen[path]; !ok {
				seen[path] = struct{}{}
				*targets = append(*targets, ScanTarget{
					Path:       path,
					TargetType: "file",
				})
			}
		}
	}
}

func isScriptExtension(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".sh", ".py", ".pl", ".rb", ".lua", ".php", ".js", ".ps1", ".bat", ".cmd":
		return true
	}
	return false
}
