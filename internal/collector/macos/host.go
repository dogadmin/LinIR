//go:build darwin

package macos

import (
	"context"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// HostCollector 通过 sysctl 和直接文件读取获取 macOS 主机信息。
// 不调用任何外部命令（sw_vers、uname 等）。
type HostCollector struct{}

func NewHostCollector() *HostCollector {
	return &HostCollector{}
}

func (c *HostCollector) CollectHostInfo(ctx context.Context) (*model.HostInfo, error) {
	info := &model.HostInfo{
		Platform:       "macos",
		Arch:           runtime.GOARCH,
		CollectionTime: time.Now(),
	}

	// 主机名: sysctl kern.hostname
	if hostname, err := unix.Sysctl("kern.hostname"); err == nil {
		info.Hostname = strings.TrimSpace(hostname)
	} else {
		info.Hostname, _ = os.Hostname()
	}

	// 内核版本: sysctl kern.osrelease
	if ver, err := unix.Sysctl("kern.osrelease"); err == nil {
		info.KernelVersion = strings.TrimSpace(ver)
	}

	// macOS 版本: 读 SystemVersion.plist
	info.NamespaceInfo = make(map[string]string)
	if ver := readMacOSVersion(); ver != "" {
		info.NamespaceInfo["macos_version"] = ver
	}

	// uptime: sysctl kern.boottime
	if bootTime, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		info.UptimeSeconds = time.Now().Unix() - bootTime.Sec
	}

	return info, nil
}

// readMacOSVersion 从 SystemVersion.plist 读取 macOS 版本号
func readMacOSVersion() string {
	data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return ""
	}
	content := string(data)

	// 简单 XML 提取
	keyTag := "<key>ProductVersion</key>"
	idx := strings.Index(content, keyTag)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(keyTag):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return rest[start+8 : end]
}
