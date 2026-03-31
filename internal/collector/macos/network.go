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
	seenTuples := make(map[string]struct{}) // 不含 PID 的 tuple key，用于合并去重

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

			// 记录不含 PID 的 tuple，用于后续合并去重
			tupleKey := connTupleKey(&result.conns[i])
			seenTuples[tupleKey] = struct{}{}
		}
	}

	// 3. 两级降级策略：
	//   完全失败 (len(conns)==0): sysctl 替换全部
	//   部分失败 (大量 access denied + 连接数可疑少): 合并 sysctl 数据补全
	var fallbackErr error
	useSysctl := false
	replaceAll := false

	if len(kinfos) > 10 && accessDeniedCount > len(kinfos)/2 {
		if len(conns) == 0 {
			useSysctl = true
			replaceAll = true
		} else if len(conns) < len(kinfos)/4 {
			useSysctl = true
			replaceAll = false
		}
	}

	if useSysctl {
		fallbackConns, fbErr := collectSysctlConnections(ctx)
		if fbErr == nil && len(fallbackConns) > 0 {
			if replaceAll {
				conns = fallbackConns
			} else {
				conns = mergeConnections(conns, fallbackConns, seenTuples)
			}
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
	return fmt.Sprintf("%d:%s", c.PID, connTupleKey(c))
}

// connTupleKey 生成不含 PID 的连接 tuple key，用于 proc/sysctl 合并去重
func connTupleKey(c *model.ConnectionInfo) string {
	return fmt.Sprintf("%s:%s:%d:%s:%d",
		c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort)
}

// mergeConnections 将 sysctl 连接合并到 proc 连接中。
// proc 连接有 PID 信息，优先保留；sysctl 连接只补充 proc 没有看到的。
func mergeConnections(procConns, sysctlConns []model.ConnectionInfo, seenTuples map[string]struct{}) []model.ConnectionInfo {
	merged := procConns
	for i := range sysctlConns {
		tupleKey := connTupleKey(&sysctlConns[i])
		if _, exists := seenTuples[tupleKey]; !exists {
			seenTuples[tupleKey] = struct{}{}
			merged = append(merged, sysctlConns[i])
		}
	}
	return merged
}
