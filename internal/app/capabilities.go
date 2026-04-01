package app

import (
	"os"
	"runtime"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/watch"
)

// detectCapabilities 检测当前平台/权限/环境的采集能力
func detectCapabilities() *model.Capabilities {
	cap := &model.Capabilities{
		Platform:          runtime.GOOS,
		RunningPrivileged: os.Getuid() == 0,
	}

	if !cap.RunningPrivileged {
		cap.Notes = append(cap.Notes, "非 root 运行，可见性显著受限")
	}

	switch runtime.GOOS {
	case "linux":
		detectLinuxCapabilities(cap)
	case "darwin":
		detectDarwinCapabilities(cap)
	default:
		cap.ProcessCollection = "unavailable"
		cap.NetworkCollection = "unavailable"
		cap.PIDAttribution = "weak"
		cap.PersistenceCollection = "unavailable"
		cap.Notes = append(cap.Notes, "平台 "+runtime.GOOS+" 仅有桩实现")
	}

	// watch 层级
	if watch.ConntrackAvailable() {
		cap.WatchModeLayer = "layer1"
	} else if watch.NfConntrackAvailable() {
		cap.WatchModeLayer = "layer2"
	} else {
		cap.WatchModeLayer = "layer3"
	}

	return cap
}

func detectLinuxCapabilities(cap *model.Capabilities) {
	// 进程采集
	if _, err := os.ReadDir("/proc/1"); err == nil {
		if cap.RunningPrivileged {
			cap.ProcessCollection = "full"
		} else {
			cap.ProcessCollection = "partial"
			cap.Notes = append(cap.Notes, "非 root: 部分 /proc/<pid> 不可读")
		}
	} else {
		cap.ProcessCollection = "unavailable"
		cap.Notes = append(cap.Notes, "/proc 不可读")
	}

	// 网络采集
	if _, err := os.Stat("/proc/net/tcp"); err == nil {
		cap.NetworkCollection = "full"
	} else {
		cap.NetworkCollection = "partial"
		cap.Notes = append(cap.Notes, "/proc/net/tcp 不可读")
	}

	// PID 归属
	if cap.RunningPrivileged {
		cap.PIDAttribution = "full"
	} else {
		cap.PIDAttribution = "partial"
		cap.Notes = append(cap.Notes, "非 root: inode→PID 映射可能不完整")
	}

	// 持久化
	cap.PersistenceCollection = "full"
}

func detectDarwinCapabilities(cap *model.Capabilities) {
	cap.ProcessCollection = "full"
	cap.PersistenceCollection = "full"

	if cap.RunningPrivileged {
		cap.NetworkCollection = "full"
		cap.PIDAttribution = "full"
	} else {
		cap.NetworkCollection = "partial"
		cap.PIDAttribution = "partial"
		cap.Notes = append(cap.Notes, "非 root: proc_pidfdinfo 受 SIP 限制")
	}
}
