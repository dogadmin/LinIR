package correlate

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Run 执行跨域关联分析。
//
// 核心关联维度：
//   1. Process ↔ Network：用 PID 关联连接到进程，标记联网的解释器
//   2. Process ↔ Persistence：用 exe 路径匹配持久化目标，发现活跃的持久化后门
//   3. Network ↔ Persistence：连接的进程如果同时有持久化项，风险更高
//
// 这一步是 LinIR 的核心价值之一——单一视图看不出的问题，
// 交叉关联后才能浮现。
func Run(result *model.CollectionResult) {
	if result == nil {
		return
	}

	// 构建索引
	procByPID := indexProcessByPID(result.Processes)
	procByExe := indexProcessByExe(result.Processes)
	connsByPID := indexConnsByPID(result.Connections)

	// 1. 关联连接到进程：填充 ProcessName
	enrichConnectionProcessName(result.Connections, procByPID)

	// 2. 关联持久化项到运行中的进程
	correlatePersistenceToProcess(result.Persistence, procByExe, connsByPID)
}

// ========== 索引构建 ==========

func indexProcessByPID(procs []model.ProcessInfo) map[int]*model.ProcessInfo {
	m := make(map[int]*model.ProcessInfo, len(procs))
	for i := range procs {
		m[procs[i].PID] = &procs[i]
	}
	return m
}

func indexProcessByExe(procs []model.ProcessInfo) map[string]*model.ProcessInfo {
	m := make(map[string]*model.ProcessInfo)
	for i := range procs {
		if procs[i].Exe != "" {
			m[procs[i].Exe] = &procs[i]
		}
	}
	return m
}

func indexConnsByPID(conns []model.ConnectionInfo) map[int][]model.ConnectionInfo {
	m := make(map[int][]model.ConnectionInfo)
	for _, c := range conns {
		if c.PID > 0 {
			m[c.PID] = append(m[c.PID], c)
		}
	}
	return m
}

// ========== 关联逻辑 ==========

// enrichConnectionProcessName 填充连接的 ProcessName 字段
func enrichConnectionProcessName(conns []model.ConnectionInfo, procByPID map[int]*model.ProcessInfo) {
	for i := range conns {
		if conns[i].PID > 0 {
			if p, ok := procByPID[conns[i].PID]; ok {
				conns[i].ProcessName = p.Name
			}
		}
	}
}

// 注意：不再标记 interpreter_established_outbound
// 解释器（python/perl/bash）联网本身不是威胁指标（pip/npm/apt 都会触发）

// correlatePersistenceToProcess 关联持久化项到运行中的进程
func correlatePersistenceToProcess(persist []model.PersistenceItem, procByExe map[string]*model.ProcessInfo, connsByPID map[int][]model.ConnectionInfo) {
	for i := range persist {
		item := &persist[i]
		if item.Target == "" {
			continue
		}

		// 查找目标路径是否对应一个正在运行的进程
		proc, running := procByExe[item.Target]
		if !running {
			continue
		}

		// 持久化项的目标正在运行
		addItemFlag(item, "target_currently_running")

		// 进一步检查：运行中的进程是否还有网络连接
		if conns, ok := connsByPID[proc.PID]; ok {
			for _, c := range conns {
				if c.State == "ESTABLISHED" {
					addItemFlag(item, "target_running_with_network")
					addProcFlag(proc, "persistent_and_networked")
					break
				}
			}
		}

		// 进程在 tmp 目录 + 持久化 = 高度可疑
		for _, flag := range proc.SuspiciousFlags {
			if flag == "exe_in_tmp" {
				addItemFlag(item, "target_running_from_tmp")
				break
			}
		}
	}
}

// ========== 辅助函数 ==========

func isInterpreter(name string) bool {
	interpreters := []string{
		"python", "python2", "python3", "perl", "ruby", "php",
		"node", "lua", "bash", "sh", "dash", "zsh", "ksh",
	}
	for _, interp := range interpreters {
		if name == interp || strings.HasPrefix(name, interp) {
			return true
		}
	}
	return false
}

func addProcFlag(p *model.ProcessInfo, flag string) {
	for _, f := range p.SuspiciousFlags {
		if f == flag {
			return
		}
	}
	p.SuspiciousFlags = append(p.SuspiciousFlags, flag)
}

func addItemFlag(item *model.PersistenceItem, flag string) {
	for _, f := range item.RiskFlags {
		if f == flag {
			return
		}
	}
	item.RiskFlags = append(item.RiskFlags, flag)
}
