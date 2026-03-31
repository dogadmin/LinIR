//go:build darwin

package macos

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// NetworkCollector 通过 proc_info syscall 采集 macOS 网络连接。
// 严禁调用 netstat、lsof、nettop 或任何外部命令。
//
// 采集策略（两级）：
//   主路线: proc_pidfdinfo 按进程遍历 FD → 获取 socket 详情（含 PID 关联）
//   兜底:   sysctl pcblist 获取全局连接视图（无 PID，但不受 SIP 限制）
//
// 当 SIP 阻止 proc_pidfdinfo 访问大多数进程时，自动降级到 sysctl 兜底。
type NetworkCollector struct{}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{}
}

func (c *NetworkCollector) CollectConnections(ctx context.Context) ([]model.ConnectionInfo, error) {
	// 1. 获取所有进程
	kinfos, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}

	// 2. 主路线：遍历每个进程，枚举 socket FD
	var conns []model.ConnectionInfo
	seen := make(map[string]struct{})

	validCount := 0
	failCount := 0
	accessDeniedCount := 0

	for _, kp := range kinfos {
		select {
		case <-ctx.Done():
			return conns, ctx.Err()
		default:
		}

		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}

		result := collectPidConnections(pid)
		failCount += result.parseFail
		accessDeniedCount += result.accessDenied
		procName := byteSliceToString(kp.Proc.P_comm[:])

		for i := range result.conns {
			key := connDedup(&result.conns[i])
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			result.conns[i].ProcessName = procName
			conns = append(conns, result.conns[i])
			validCount++
		}
	}

	// 3. 兜底：如果主路线因 SIP 几乎完全失败，用 sysctl pcblist 获取全局视图
	var fallbackErr error
	if len(conns) == 0 && len(kinfos) > 10 && accessDeniedCount > len(kinfos)/2 {
		fallbackConns, fbErr := collectSysctlConnections(ctx)
		if fbErr == nil && len(fallbackConns) > 0 {
			conns = fallbackConns
		}
		fallbackErr = fmt.Errorf(
			"proc_pidfdinfo 被 SIP 阻止 (%d/%d 进程访问被拒绝)，已降级到 sysctl pcblist (无 PID 关联)",
			accessDeniedCount, len(kinfos))
	}

	// 4. 如果校验失败率过高，标记低可信度
	total := validCount + failCount
	if total > 0 && failCount > total/2 {
		for i := range conns {
			conns[i].Confidence = "low"
		}
	}

	return conns, fallbackErr
}

// connDedup 生成连接的去重 key（含 PID，避免多进程共享 socket 时丢数据）
func connDedup(c *model.ConnectionInfo) string {
	return fmt.Sprintf("%d:%s:%s:%d:%s:%d",
		c.PID, c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)
}
