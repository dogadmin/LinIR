//go:build darwin

package macos

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/pkg/userutil"

	"github.com/dogadmin/LinIR/internal/model"
)

// ProcessCollector 通过 sysctl KERN_PROC 枚举进程。
// 严禁调用 ps、top 或任何外部命令。
//
// 数据源：
//   sysctl kern.proc.all → kinfo_proc 结构体数组
//   proc_pidpath (syscall 336) → 进程完整路径
//   sysctl KERN_PROCARGS2 → 命令行参数
type ProcessCollector struct{}

func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{}
}

func (c *ProcessCollector) CollectProcesses(ctx context.Context) ([]model.ProcessInfo, error) {
	kinfos, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %w", err)
	}

	userCache := make(map[int]string)
	result := make([]model.ProcessInfo, 0, len(kinfos))

	for i := range kinfos {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		proc := kinfoToProcessInfo(&kinfos[i], userCache)
		if proc != nil {
			result = append(result, *proc)
		}
	}

	return result, nil
}

func kinfoToProcessInfo(kp *unix.KinfoProc, userCache map[int]string) *model.ProcessInfo {
	pid := int(kp.Proc.P_pid)
	if pid <= 0 {
		return nil
	}

	proc := &model.ProcessInfo{
		PID:        pid,
		PPID:       int(kp.Eproc.Ppid),
		UID:        int(kp.Eproc.Ucred.Uid),
		Source:     "native_api",
		Confidence: "high",
	}
	if kp.Eproc.Ucred.Ngroups > 0 {
		proc.GID = int(kp.Eproc.Ucred.Groups[0])
	}

	// 进程名
	proc.Name = byteSliceToString(kp.Proc.P_comm[:])

	// 完整路径
	proc.Exe = procPidPath(pid)

	// 命令行参数
	proc.Cmdline = getProcArgs(pid)

	// 启动时间
	if kp.Proc.P_starttime.Sec > 0 {
		t := time.Unix(kp.Proc.P_starttime.Sec, int64(kp.Proc.P_starttime.Usec)*1000)
		proc.StartTime = t.Format(time.RFC3339)
	}

	// 用户名
	proc.Username = userutil.ResolveUsername(proc.UID, userCache)

	// 初步可疑标记
	flagSuspicious(proc)

	return proc
}

// procPidPath 通过 SYS_proc_info (syscall 336) 获取进程路径
func procPidPath(pid int) string {
	buf := make([]byte, 4096)
	// proc_pidpath 是 proc_info syscall 的包装
	// __proc_info(PROC_INFO_CALL_PIDINFO=2, pid, PROC_PIDPATHINFO=11, 0, buf, bufsize)
	ret, _, _ := unix.Syscall6(
		336, // SYS_proc_info
		2,   // PROC_INFO_CALL_PIDINFO
		uintptr(pid),
		11, // PROC_PIDPATHINFO
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

// getProcArgs 通过 sysctl KERN_PROCARGS2 获取命令行参数
func getProcArgs(pid int) []string {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(raw) < 4 {
		return nil
	}

	// 格式: int32(argc) + execpath\0 + padding\0... + argv[0]\0 + ...
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	if argc <= 0 || argc > 1024 {
		return nil
	}

	pos := 4
	// 跳过 execpath
	for pos < len(raw) && raw[pos] != 0 {
		pos++
	}
	// 跳过 padding
	for pos < len(raw) && raw[pos] == 0 {
		pos++
	}

	var args []string
	for i := 0; i < argc && pos < len(raw); i++ {
		start := pos
		for pos < len(raw) && raw[pos] != 0 {
			pos++
		}
		if pos > start {
			args = append(args, string(raw[start:pos]))
		}
		pos++
	}
	return args
}

func byteSliceToString(s []byte) string {
	for i, b := range s {
		if b == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}


func flagSuspicious(proc *model.ProcessInfo) {
	tmpPrefixes := []string{"/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/"}
	for _, prefix := range tmpPrefixes {
		if strings.HasPrefix(proc.Exe, prefix) {
			proc.SuspiciousFlags = append(proc.SuspiciousFlags, "exe_in_tmp")
			break
		}
	}
	interpreters := []string{"python", "perl", "ruby", "bash", "sh", "zsh", "php", "node", "osascript"}
	for _, interp := range interpreters {
		if proc.Name == interp || strings.HasPrefix(proc.Name, interp) {
			proc.SuspiciousFlags = append(proc.SuspiciousFlags, "interpreter")
			break
		}
	}
	if proc.Exe == "" && len(proc.Cmdline) > 0 {
		proc.SuspiciousFlags = append(proc.SuspiciousFlags, "exe_unreadable")
		proc.Confidence = "medium"
	}
}
