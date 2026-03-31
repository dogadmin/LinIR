//go:build linux

package linux

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/procfs"
	"github.com/dogadmin/LinIR/pkg/userutil"
)

// ProcessCollector 通过直接读取 /proc 枚举进程。
// 严禁调用 ps、top 或任何外部命令。
//
// 数据源：
//   /proc/<pid>/stat     — PID, PPID, state, 启动时间, 线程数, 内存
//   /proc/<pid>/status   — 进程名, UID, GID, namespace PID
//   /proc/<pid>/cmdline  — 完整命令行（\0 分隔）
//   /proc/<pid>/exe      — 可执行文件路径 (readlink)
//   /proc/<pid>/cwd      — 工作目录 (readlink)
//   /proc/<pid>/environ  — 环境变量（\0 分隔，可选采集）
//   /proc/<pid>/fd/      — 文件描述符数量 + socket inode
//   /proc/<pid>/maps     — 映射库摘要
//
// 为什么不用 ps：
//   ps 本身可能被替换或受 LD_PRELOAD 影响，输出不可信。
//   直接读 /proc 在用户态 rootkit 场景下仍可能被绕过（需要内核级隐藏），
//   但比依赖用户态命令可靠得多。
type ProcessCollector struct {
	procRoot   string
	collectEnv bool
	hashExe    bool
}

// NewProcessCollector 创建进程采集器
func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{procRoot: "/proc"}
}

// SetOptions 设置采集选项
func (c *ProcessCollector) SetOptions(collectEnv, hashExe bool) {
	c.collectEnv = collectEnv
	c.hashExe = hashExe
}

func (c *ProcessCollector) CollectProcesses(ctx context.Context) ([]model.ProcessInfo, error) {
	// 设置 procfs 的根路径
	procfs.ProcRoot = c.procRoot

	// 1. 获取所有 PID
	pids, err := procfs.ListPIDs()
	if err != nil {
		return nil, fmt.Errorf("枚举 PID 失败: %w", err)
	}

	// 2. 获取 boot time 用于计算进程启动的绝对时间
	bootTime, _ := procfs.ReadBootTime()
	clockTick := procfs.ReadClockTick()

	// 3. 预构建 UID -> username 缓存
	userCache := make(map[int]string)

	// 4. 遍历每个 PID 采集信息
	processes := make([]model.ProcessInfo, 0, len(pids))
	for _, pid := range pids {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return processes, ctx.Err()
		default:
		}

		proc, err := c.collectOne(pid, bootTime, clockTick, userCache)
		if err != nil {
			// 进程可能已经退出，跳过
			continue
		}
		if proc != nil {
			processes = append(processes, *proc)
		}
	}

	return processes, nil
}

// collectOne 采集单个进程的所有信息
func (c *ProcessCollector) collectOne(pid int, bootTime, clockTick uint64, userCache map[int]string) (*model.ProcessInfo, error) {
	// 先读 stat，如果失败说明进程已退出
	stat, err := procfs.ReadStat(pid)
	if err != nil || stat == nil {
		return nil, err
	}

	proc := &model.ProcessInfo{
		PID:        stat.PID,
		PPID:       stat.PPID,
		Source:     "procfs",
		Confidence: "high",
	}

	// 进程名：优先从 status 获取（不受 16 字符截断限制）
	status, _ := procfs.ReadStatus(pid)
	if status != nil {
		proc.Name = status.Name
		proc.UID = status.UID[0]  // Real UID
		proc.GID = status.GID[0]  // Real GID
	} else {
		// 回退到 stat 中的 comm（可能被截断为 15 字符）
		proc.Name = stat.Comm
	}

	// UID -> Username 解析
	proc.Username = userutil.ResolveUsername(proc.UID, userCache)

	// 可执行文件路径
	exe := procfs.ReadExe(pid)
	proc.Exe = exe
	// 检查 "(deleted)" 标记
	if strings.HasSuffix(exe, " (deleted)") {
		proc.Exe = strings.TrimSuffix(exe, " (deleted)")
		proc.SuspiciousFlags = append(proc.SuspiciousFlags, "exe_deleted")
	}

	// 命令行
	cmdline, _ := procfs.ReadCmdline(pid)
	proc.Cmdline = cmdline

	// 工作目录
	proc.Cwd = procfs.ReadCwd(pid)

	// 启动时间：从 clock ticks 转换为绝对时间
	if bootTime > 0 && clockTick > 0 && stat.StartTime > 0 {
		startSec := bootTime + stat.StartTime/clockTick
		t := time.Unix(int64(startSec), 0)
		proc.StartTime = t.Format(time.RFC3339)
	}

	// 文件描述符计数 + socket inode 收集
	fdCount, socketInodes, _ := procfs.ReadFDs(pid)
	proc.FDCount = fdCount
	proc.SocketInodes = socketInodes

	// maps 摘要（映射的库文件列表）
	mapsSummary, _ := procfs.ReadMapsSummary(pid)
	proc.MapsSummary = mapsSummary

	// 环境变量采样（可选，敏感数据）
	if c.collectEnv {
		env, _ := procfs.ReadEnviron(pid, 50) // 最多采集 50 个
		proc.EnvironSample = env
	}

	// 可疑标记初步检测
	c.flagSuspicious(proc)

	return proc, nil
}

// flagSuspicious 基于采集到的数据标记可疑项
// 这是初步标记，后续 process.Analyze() 会做更深入的分析
func (c *ProcessCollector) flagSuspicious(proc *model.ProcessInfo) {
	// exe 路径在临时目录
	tmpPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/dev/mqueue/"}
	for _, prefix := range tmpPrefixes {
		if strings.HasPrefix(proc.Exe, prefix) {
			proc.SuspiciousFlags = append(proc.SuspiciousFlags, "exe_in_tmp")
			break
		}
	}

	// exe 路径为空但 cmdline 不为空（可能是内核线程，也可能是隐藏进程）
	if proc.Exe == "" && len(proc.Cmdline) > 0 {
		proc.SuspiciousFlags = append(proc.SuspiciousFlags, "exe_unreadable")
		proc.Confidence = "medium"
	}

	// 常见解释器进程
	interpreters := []string{"python", "perl", "ruby", "bash", "sh", "dash", "zsh",
		"php", "node", "lua", "awk", "nawk", "gawk"}
	baseName := proc.Name
	for _, interp := range interpreters {
		if baseName == interp || strings.HasPrefix(baseName, interp) {
			proc.SuspiciousFlags = append(proc.SuspiciousFlags, "interpreter")
			break
		}
	}

	// 进程名和 exe 基本名不一致（可能在伪装进程名）
	if proc.Exe != "" && proc.Name != "" {
		exeBase := basename(proc.Exe)
		if exeBase != "" && exeBase != proc.Name && !strings.HasPrefix(exeBase, proc.Name) {
			proc.SuspiciousFlags = append(proc.SuspiciousFlags, "name_exe_mismatch")
		}
	}
}

// basename 返回路径的最后一个组件
func basename(path string) string {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}
