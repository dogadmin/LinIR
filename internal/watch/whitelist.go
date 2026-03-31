package watch

import (
	"bufio"
	"os"
	"strings"
)

// Whitelist 管理进程/路径/IOC 的白名单
type Whitelist struct {
	processes map[string]struct{} // 进程名白名单
	paths     map[string]struct{} // exe 路径前缀白名单
	iocs      map[string]struct{} // IOC 值白名单（记录但不告警）
}

// LoadWhitelist 从文件加载白名单。
// 格式：每行一条，前缀标识类型：
//   process:sshd
//   path:/usr/lib/systemd/
//   ioc:1.2.3.4
// 无前缀默认为 process 名
func LoadWhitelist(path string) (*Whitelist, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	wl := &Whitelist{
		processes: make(map[string]struct{}),
		paths:     make(map[string]struct{}),
		iocs:      make(map[string]struct{}),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "process:") {
			wl.processes[strings.TrimPrefix(line, "process:")] = struct{}{}
		} else if strings.HasPrefix(line, "path:") {
			wl.paths[strings.TrimPrefix(line, "path:")] = struct{}{}
		} else if strings.HasPrefix(line, "ioc:") {
			wl.iocs[strings.TrimPrefix(line, "ioc:")] = struct{}{}
		} else {
			// 默认为进程名
			wl.processes[line] = struct{}{}
		}
	}

	return wl, scanner.Err()
}

// ShouldSuppress 判断命中事件是否应被白名单抑制
func (wl *Whitelist) ShouldSuppress(hit HitEvent) bool {
	// IOC 白名单
	if _, ok := wl.iocs[hit.IOC.Value]; ok {
		return true
	}

	// 进程名白名单
	if hit.Connection.ProcessName != "" {
		if _, ok := wl.processes[hit.Connection.ProcessName]; ok {
			return true
		}
	}

	return false
}

// ShouldSuppressProcess 判断进程是否在白名单中
func (wl *Whitelist) ShouldSuppressProcess(name, exePath string) bool {
	if _, ok := wl.processes[name]; ok {
		return true
	}
	for prefix := range wl.paths {
		if strings.HasPrefix(exePath, prefix) {
			return true
		}
	}
	return false
}
