//go:build linux

package linux

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/procfs"
	"github.com/dogadmin/LinIR/pkg/sysparse"
)

// HostCollector 通过直接读取 /proc、/sys、/etc 下的文件采集主机信息。
// 不调用任何外部命令。
type HostCollector struct{}

func NewHostCollector() *HostCollector {
	return &HostCollector{}
}

func (c *HostCollector) CollectHostInfo(ctx context.Context) (*model.HostInfo, error) {
	info := &model.HostInfo{
		Platform:       "linux",
		Arch:           runtime.GOARCH,
		CollectionTime: time.Now(),
	}

	// 主机名：直接读 /proc/sys/kernel/hostname
	if hostname, err := procfs.ReadFileString("/proc/sys/kernel/hostname"); err == nil {
		info.Hostname = strings.TrimSpace(hostname)
	} else {
		// 回退到 os.Hostname()
		info.Hostname, _ = os.Hostname()
	}

	// 内核版本：/proc/sys/kernel/osrelease
	if ver, err := procfs.ReadFileString("/proc/sys/kernel/osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(ver)
	}

	// uptime：/proc/uptime 第一个字段是秒数（浮点）
	if uptime, err := procfs.ReadFileString("/proc/uptime"); err == nil {
		fields := strings.Fields(uptime)
		if len(fields) >= 1 {
			// 去掉小数部分
			sec := fields[0]
			if dotIdx := strings.IndexByte(sec, '.'); dotIdx >= 0 {
				sec = sec[:dotIdx]
			}
			var v int64
			for _, ch := range sec {
				v = v*10 + int64(ch-'0')
			}
			info.UptimeSeconds = v
		}
	}

	// 容器化检测
	info.Containerized = detectContainerized()

	// namespace 信息
	info.NamespaceInfo = readNamespaceInfo()

	// 操作系统发行版信息（合并到 Platform 注释或 KernelVersion 后面）
	if rel, err := sysparse.ParseOSRelease("/etc/os-release"); err == nil && rel.PrettyName != "" {
		// 把发行版信息附加到 Platform 中用于展示
		info.Platform = "linux" // 保持标准值
		// 记录在 NamespaceInfo 中避免改动 Platform 字段语义
		if info.NamespaceInfo == nil {
			info.NamespaceInfo = make(map[string]string)
		}
		info.NamespaceInfo["os_pretty_name"] = rel.PrettyName
		info.NamespaceInfo["os_id"] = rel.ID
		info.NamespaceInfo["os_version_id"] = rel.VersionID
	}

	return info, nil
}

// detectContainerized 检测是否在容器中运行
func detectContainerized() bool {
	// 检查 /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// 检查 /run/.containerenv (Podman)
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	// 检查 /proc/1/cgroup 中的容器标识
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}
	return false
}

// readNamespaceInfo 读取当前进程的 namespace 标识
func readNamespaceInfo() map[string]string {
	nsTypes := []string{"pid", "net", "mnt", "uts", "ipc", "user", "cgroup"}
	nsInfo := make(map[string]string)
	for _, ns := range nsTypes {
		target, err := os.Readlink("/proc/self/ns/" + ns)
		if err == nil {
			nsInfo[ns+"_ns"] = target
		}
	}
	if len(nsInfo) == 0 {
		return nil
	}
	return nsInfo
}
