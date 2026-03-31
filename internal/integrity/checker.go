package integrity

import (
	"context"
	"fmt"

	"github.com/dogadmin/LinIR/internal/model"
)

// Check 执行跨数据源的可见性与完整性检查。
//
// 设计原理：
// LinIR 不追求"确认 rootkit 名称"，而是发现数据源之间的不一致。
// 如果进程列表里有 PID 引用了一个不存在的 PPID，或者网络连接
// 关联到一个不在进程列表中的 PID，这些不一致本身就是重要的取证证据。
//
// 检查维度：
//   1. 进程视图不一致 — PPID 不存在、exe 不可读/已删除
//   2. 网络视图不一致 — 连接的 PID 不在进程列表中、orphan 连接
//   3. 文件视图不一致 — 持久化目标缺失
//   4. 模块视图不一致 — /proc/modules vs /sys/module (Linux)
//   5. 内核 taint 状态 (Linux)
func Check(ctx context.Context, result *model.CollectionResult) (*model.IntegrityResult, error) {
	ir := &model.IntegrityResult{}
	if result == nil {
		return ir, nil
	}

	// 构建 PID 集合
	pidSet := make(map[int]struct{}, len(result.Processes))
	for _, p := range result.Processes {
		pidSet[p.PID] = struct{}{}
	}

	checkProcessView(ir, result.Processes, pidSet)
	checkNetworkView(ir, result.Connections, pidSet)
	checkFileView(ir, result.Persistence)

	// 平台特定内核检查（Linux: /proc/modules vs /sys/module, kernel taint）
	platformKernelCheck(ctx, ir)

	evaluateRootkitSuspicion(ir)

	return ir, nil
}

// checkProcessView 检查进程视图中的不一致
func checkProcessView(ir *model.IntegrityResult, procs []model.ProcessInfo, pidSet map[int]struct{}) {
	for _, p := range procs {
		// PPID 引用了不存在的进程（PID 0/1 除外）
		if p.PPID > 1 {
			if _, ok := pidSet[p.PPID]; !ok {
				ir.ProcessViewMismatch = append(ir.ProcessViewMismatch,
					fmt.Sprintf("PID %d (%s) 的 PPID %d 不在进程列表中", p.PID, p.Name, p.PPID))
			}
		}

		// 有 cmdline 但 exe 不可读
		if p.Exe == "" && len(p.Cmdline) > 0 {
			ir.ProcessViewMismatch = append(ir.ProcessViewMismatch,
				fmt.Sprintf("PID %d (%s) 有命令行但 exe 路径不可读", p.PID, p.Name))
		}

		// exe 已删除
		for _, flag := range p.SuspiciousFlags {
			if flag == "exe_deleted" {
				ir.ProcessViewMismatch = append(ir.ProcessViewMismatch,
					fmt.Sprintf("PID %d (%s) 的可执行文件已被从磁盘删除", p.PID, p.Name))
			}
		}
	}
}

// checkNetworkView 检查网络视图中的不一致
func checkNetworkView(ir *model.IntegrityResult, conns []model.ConnectionInfo, pidSet map[int]struct{}) {
	orphanCount := 0
	pidMissingCount := 0

	for _, c := range conns {
		if c.Proto == "unix" || c.SocketInode == 0 {
			continue
		}

		if c.PID == 0 {
			orphanCount++
			if orphanCount <= 10 {
				ir.NetworkViewMismatch = append(ir.NetworkViewMismatch,
					fmt.Sprintf("%s %s:%d->%s:%d (%s) inode=%d 无归属进程",
						c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.State, c.SocketInode))
			}
		} else {
			if _, ok := pidSet[c.PID]; !ok {
				pidMissingCount++
				if pidMissingCount <= 10 {
					ir.NetworkViewMismatch = append(ir.NetworkViewMismatch,
						fmt.Sprintf("%s %s:%d->%s:%d 关联 PID %d 不在进程列表中",
							c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.PID))
				}
			}
		}
	}

	if orphanCount > 10 {
		ir.NetworkViewMismatch = append(ir.NetworkViewMismatch,
			fmt.Sprintf("... 共 %d 个无归属进程的连接(仅显示前 10)", orphanCount))
	}
	if pidMissingCount > 10 {
		ir.NetworkViewMismatch = append(ir.NetworkViewMismatch,
			fmt.Sprintf("... 共 %d 个关联到不存在进程的连接(仅显示前 10)", pidMissingCount))
	}
}

// checkFileView 检查持久化目标文件视图不一致
func checkFileView(ir *model.IntegrityResult, persist []model.PersistenceItem) {
	for _, p := range persist {
		for _, flag := range p.RiskFlags {
			if flag == "target_missing" {
				ir.FileViewMismatch = append(ir.FileViewMismatch,
					fmt.Sprintf("%s (%s) 目标 %s 不存在", p.Path, p.Type, p.Target))
			}
		}
	}
}

// evaluateRootkitSuspicion 综合判断
func evaluateRootkitSuspicion(ir *model.IntegrityResult) {
	weight := 0
	weight += len(ir.ProcessViewMismatch) * 5
	weight += len(ir.NetworkViewMismatch) * 5
	weight += len(ir.FileViewMismatch) * 3
	weight += len(ir.ModuleViewMismatch) * 15
	weight += len(ir.VisibilityAnomalies) * 10

	if weight >= 30 {
		ir.RootkitSuspected = true
		ir.RecommendedAction = append(ir.RecommendedAction,
			"多数据源存在不一致，建议离线取证复核")
	}
	if len(ir.ModuleViewMismatch) > 0 {
		ir.RootkitSuspected = true
		ir.RecommendedAction = append(ir.RecommendedAction,
			"内核模块视图不一致，强烈建议通过外部引导环境深度检查")
	}
	if ir.KernelTaint != "" && ir.KernelTaint != "0" {
		ir.RecommendedAction = append(ir.RecommendedAction,
			"内核 taint 非零，可能加载了非标准模块")
	}
}
