//go:build darwin

package macos

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// NetworkCollector 通过 proc_info syscall + sysctl pcblist 采集 macOS 网络连接。
// 严禁调用 netstat、lsof、nettop 或任何外部命令。
//
// 采集策略（双源合并）：
//   1. proc_pidfdinfo: 按进程遍历 FD → 获取 socket 详情（含 PID 关联）
//   2. sysctl pcblist: 全局连接视图（无 PID，但不受 SIP 限制）
//   3. 合并: proc 有 PID 信息优先保留，sysctl 补充 proc 看不到的连接
//
// 始终运行两种采集，避免 SIP 各种失败模式导致漏采。
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

	// 构建 PID → 进程名 映射，供 sysctl 连接补全 ProcessName
	pidNameMap := make(map[int]string, len(kinfos))
	for _, kp := range kinfos {
		pid := int(kp.Proc.P_pid)
		if pid > 0 {
			pidNameMap[pid] = byteSliceToString(kp.Proc.P_comm[:])
		}
	}

	// 2. 主路线：proc_pidfdinfo（有 PID 关联）
	var conns []model.ConnectionInfo
	seen := make(map[string]struct{})
	seenTuples := make(map[string]struct{})

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

			tupleKey := connTupleKey(&result.conns[i])
			seenTuples[tupleKey] = struct{}{}
		}
	}

	procCount := len(conns)

	// 3. 始终运行 sysctl 采集并合并（不再依赖条件判断）
	var supplementErr error
	sysctlConns, fbErr := collectSysctlConnections(ctx)
	if fbErr == nil && len(sysctlConns) > 0 {
		conns = mergeConnections(conns, sysctlConns, seenTuples)
	}

	// 为 sysctl 连接补全 ProcessName（sysctl 可能提取到 PID 但没有进程名）
	for i := range conns {
		if conns[i].PID > 0 && conns[i].ProcessName == "" {
			if name, ok := pidNameMap[conns[i].PID]; ok {
				conns[i].ProcessName = name
			}
		}
	}

	// 如果 proc 采到 0 条但 sysctl 有数据，标记降级
	if procCount == 0 && len(conns) > 0 {
		supplementErr = fmt.Errorf(
			"proc_pidfdinfo 未采集到连接 (SIP 限制)，已通过 sysctl pcblist_n 补充 %d 条",
			len(conns))
	}

	// 4. 如果校验失败率过高，标记低可信度
	total := validCount + failCount
	if total > 0 && failCount > total/2 {
		for i := range conns {
			conns[i].Confidence = "low"
		}
	}

	return conns, supplementErr
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
