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
// 实现策略：
//   主路线: 遍历所有进程 → 枚举每个进程的 FD → 过滤 socket FD →
//          通过 PROC_PIDFDSOCKETINFO 获取 socket 详情 → 解析 buffer
//   优势: PID 关联免费获得（按 PID 遍历），sockaddr 布局稳定
//   限制: 非 root 时无法看到其他用户进程的 FD，此时 Confidence 降为 "low"
//
// 为什么不用 netstat/lsof：
//   这些命令本身可被替换，输出可被篡改。
//   直接走 syscall 在用户态 rootkit 场景下更可信。
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

	// 2. 遍历每个进程，枚举 socket FD
	var conns []model.ConnectionInfo
	seen := make(map[string]struct{}) // 去重 key

	validCount := 0
	failCount := 0

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

	// 3. 如果校验失败率过高，说明偏移可能错了
	total := validCount + failCount
	if total > 0 && failCount > total/2 {
		// 降级：将所有连接标记为低可信度
		for i := range conns {
			conns[i].Confidence = "low"
		}
	}

	return conns, nil
}

// connDedup 生成连接的去重 key（含 PID，避免多进程共享 socket 时丢数据）
func connDedup(c *model.ConnectionInfo) string {
	return fmt.Sprintf("%d:%s:%s:%d:%s:%d",
		c.PID, c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)
}
