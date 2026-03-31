//go:build linux

package procfs

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadCmdline 解析 /proc/[pid]/cmdline，返回参数列表
// cmdline 中参数以 \0 分隔。如果进程是内核线程，cmdline 可能为空。
func ReadCmdline(pid int) ([]string, error) {
	path := fmt.Sprintf("%s/%d/cmdline", ProcRoot, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	// 去掉末尾的 \0
	content := strings.TrimRight(string(data), "\x00")
	if content == "" {
		return nil, nil
	}
	return strings.Split(content, "\x00"), nil
}

// ReadExe 读取 /proc/[pid]/exe 符号链接的目标路径
// 返回空字符串表示无法读取（权限不足或进程已退出）
func ReadExe(pid int) string {
	path := fmt.Sprintf("%s/%d/exe", ProcRoot, pid)
	return ReadLink(path)
}

// ReadCwd 读取 /proc/[pid]/cwd 符号链接的目标路径
func ReadCwd(pid int) string {
	path := fmt.Sprintf("%s/%d/cwd", ProcRoot, pid)
	return ReadLink(path)
}

// ReadEnviron 解析 /proc/[pid]/environ，返回环境变量 map
// environ 中条目以 \0 分隔。需要 root 权限或者进程归属当前用户。
// maxEntries 限制最大采集条数，避免输出过大。0 表示不限制。
func ReadEnviron(pid int, maxEntries int) (map[string]string, error) {
	path := fmt.Sprintf("%s/%d/environ", ProcRoot, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	envMap := make(map[string]string)
	entries := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	count := 0
	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		envMap[parts[0]] = parts[1]
		count++
		if maxEntries > 0 && count >= maxEntries {
			break
		}
	}
	return envMap, nil
}

// FDInfo 记录一个文件描述符的信息
type FDInfo struct {
	FD     int
	Target string // 符号链接目标
	IsSocket bool
	SocketInode uint64
}

// ReadFDs 枚举 /proc/[pid]/fd/ 下的所有文件描述符
// 返回 FD 列表和 socket inode 列表
func ReadFDs(pid int) (fdCount int, socketInodes []uint64, err error) {
	fdDir := fmt.Sprintf("%s/%d/fd", ProcRoot, pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return 0, nil, nil
		}
		return 0, nil, err
	}

	fdCount = len(entries)
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, entry.Name()))
		if err != nil {
			continue
		}
		// 格式: "socket:[12345]"
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodeStr := target[8 : len(target)-1]
			if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
				socketInodes = append(socketInodes, inode)
			}
		}
	}
	return fdCount, socketInodes, nil
}

// ReadBootTime 从 /proc/stat 读取系统启动时间（Unix 时间戳秒数）
func ReadBootTime() (uint64, error) {
	content, err := ReadFileString(ProcRoot + "/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("procfs: btime not found in /proc/stat")
}

// ReadClockTick 返回系统的 clock ticks per second (通常是 100)
// 在 Linux 上通过 sysconf(_SC_CLK_TCK) 获取，Go 中直接用常量 100
func ReadClockTick() uint64 {
	// 在绝大多数 Linux 系统上 HZ=100
	// Go 的 runtime 也假设 _SC_CLK_TCK=100
	return 100
}
