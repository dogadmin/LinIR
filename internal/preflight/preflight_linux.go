//go:build linux

package preflight

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
)

func platformPreflight(result *model.PreflightResult, cfg *config.Config) {
	// 1. /proc 挂载检查——这是 Linux 采集的生命线
	checkProcMount(result)

	// 2. /sys 可达性
	checkSysMount(result)

	// 3. /etc/ld.so.preload 系统级劫持
	checkLdSoPreload(result)

	// 4. 容器 / namespace / chroot 检测
	checkContainerized(result)

	// 5. 关键系统命令元数据检查（仅检查文件属性，不执行命令）
	checkCriticalBinaries(result)

	// 6. shell profile 污染检查
	checkShellProfiles(result)

	// 7. 磁盘空间检查（输出目录）
	checkDiskSpace(result, cfg.OutputDir)
}

// checkProcMount 检查 /proc 是否正常挂载
func checkProcMount(result *model.PreflightResult) {
	// /proc/self/stat 是最基本的自检文件
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		result.VisibilityRisk = append(result.VisibilityRisk,
			"/proc 未挂载或不可访问: 无法进行进程枚举和网络连接采集")
		return
	}

	// 检查 /proc 的挂载类型是否正确
	// 通过读 /proc/self/mountinfo 确认
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		result.Notes = append(result.Notes, "无法读取 /proc/self/mountinfo")
		return
	}
	content := string(data)
	foundProc := false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		// mountinfo 格式: ... mount_point ... - fs_type ...
		for i, f := range fields {
			if f == "/proc" && i < len(fields)-3 {
				foundProc = true
				break
			}
		}
	}
	if !foundProc {
		result.Notes = append(result.Notes, "/proc 在 mountinfo 中未找到标准挂载记录")
	}

	// 检查 /proc/net 是否可读
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		result.VisibilityRisk = append(result.VisibilityRisk,
			"/proc/net/tcp 不可读: 网络连接采集可能受限")
	}
}

// checkSysMount 检查 /sys 可达性
func checkSysMount(result *model.PreflightResult) {
	if _, err := os.Stat("/sys"); err != nil {
		result.Notes = append(result.Notes, "/sys 不可访问: 内核模块对比检查将受限")
		return
	}
	if _, err := os.Stat("/sys/module"); err != nil {
		result.Notes = append(result.Notes, "/sys/module 不可访问: 模块可见性对比将受限")
	}
}

// checkLdSoPreload 检查系统级预加载配置
func checkLdSoPreload(result *model.PreflightResult) {
	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return // 文件不存在是正常的
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	// /etc/ld.so.preload 有内容——这在正常生产环境中非常少见
	result.LoaderAnomaly = append(result.LoaderAnomaly,
		"/etc/ld.so.preload 存在且有内容(系统级 preload，极少见于正常环境)")

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.LoaderAnomaly = append(result.LoaderAnomaly,
			"/etc/ld.so.preload 条目: "+line)
	}
}

// checkContainerized 检测当前是否在容器/namespace/chroot 环境中运行
func checkContainerized(result *model.PreflightResult) {
	indicators := []struct {
		path string
		desc string
	}{
		{"/.dockerenv", "Docker 容器"},
		{"/run/.containerenv", "Podman 容器"},
	}

	for _, ind := range indicators {
		if _, err := os.Stat(ind.path); err == nil {
			result.Notes = append(result.Notes,
				"检测到容器环境("+ind.desc+"): 采集范围仅限于容器内部")
		}
	}

	// 检查 /proc/1/cgroup 判断是否在 cgroup 隔离中
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") ||
			strings.Contains(content, "containerd") || strings.Contains(content, "lxc") {
			result.Notes = append(result.Notes,
				"cgroup 显示容器化环境: "+strings.TrimSpace(strings.Split(content, "\n")[0]))
		}
	}

	// 检查 chroot：比较 /proc/1/root 和 /proc/self/root
	initRoot, err1 := os.Readlink("/proc/1/root")
	selfRoot, err2 := os.Readlink("/proc/self/root")
	if err1 == nil && err2 == nil && initRoot != selfRoot {
		result.Notes = append(result.Notes,
			"可能处于 chroot 环境: init root="+initRoot+" self root="+selfRoot)
	}

	// 检查 PID namespace：/proc/self/status 中的 NSpid 如果有多个值说明在 PID namespace 中
	data, err = os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				fields := strings.Fields(line)
				if len(fields) > 2 { // "NSpid: <host_pid> <ns_pid>"
					result.Notes = append(result.Notes,
						"检测到 PID namespace 隔离: "+strings.TrimSpace(line))
				}
			}
		}
	}
}

// checkCriticalBinaries 检查关键系统命令的文件元数据
// 注意：我们不执行这些命令，只检查文件属性是否异常
func checkCriticalBinaries(result *model.PreflightResult) {
	// 关键命令及其预期属性
	criticalBins := []struct {
		paths []string // 可能的路径
		name  string
	}{
		{[]string{"/bin/ls", "/usr/bin/ls"}, "ls"},
		{[]string{"/bin/ps", "/usr/bin/ps"}, "ps"},
		{[]string{"/bin/netstat", "/usr/bin/netstat", "/sbin/ss", "/usr/sbin/ss"}, "netstat/ss"},
		{[]string{"/bin/cat", "/usr/bin/cat"}, "cat"},
		{[]string{"/bin/bash", "/usr/bin/bash"}, "bash"},
		{[]string{"/bin/sh", "/usr/bin/sh"}, "sh"},
	}

	for _, bin := range criticalBins {
		for _, path := range bin.paths {
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}

			// 检查是否为符号链接指向异常目标
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err == nil {
					if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/dev/shm/") {
						result.VisibilityRisk = append(result.VisibilityRisk,
							bin.name+" ("+path+") 符号链接指向可疑路径: "+target)
					}
				}
			}

			// 检查是否最近被修改（获取 stat 信息）
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}

			// 检查文件所有者是否为 root
			if stat.Uid != 0 {
				result.VisibilityRisk = append(result.VisibilityRisk,
					bin.name+" ("+path+") 所有者不是 root (uid="+strconv.FormatUint(uint64(stat.Uid), 10)+")")
			}

			// 检查是否 world-writable
			if info.Mode().Perm()&0002 != 0 {
				result.VisibilityRisk = append(result.VisibilityRisk,
					bin.name+" ("+path+") 是 world-writable")
			}

			break // 找到一个路径就够了
		}
	}
}

// checkShellProfiles 检查全局 shell profile 文件是否有可疑内容
func checkShellProfiles(result *model.PreflightResult) {
	profiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/bashrc",
		"/etc/zshrc",
		"/etc/profile.d",
	}

	for _, path := range profiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		// 如果是目录（如 /etc/profile.d），检查里面的文件
		if info.IsDir() {
			checkProfileDir(result, path)
			continue
		}

		// 检查文件内容中的可疑模式
		checkProfileFile(result, path)
	}
}

func checkProfileDir(result *model.PreflightResult, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		checkProfileFile(result, path)
	}
}

func checkProfileFile(result *model.PreflightResult, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// 可疑模式
	// 只检查明确的恶意指标，不标记默认系统配置中的正常内容
	// eval/base64/curl/wget/alias 在默认 /etc/profile 和 bash.bashrc 中极为常见
	suspiciousPatterns := []struct {
		pattern string
		desc    string
	}{
		{"/dev/tcp/", "bash /dev/tcp 网络连接(反弹 shell 常用手法)"},
		{"export LD_PRELOAD", "LD_PRELOAD 设置"},
		{"export DYLD_INSERT", "DYLD 注入设置"},
	}

	for _, sp := range suspiciousPatterns {
		if strings.Contains(content, sp.pattern) {
			result.ShellProfileAnomaly = append(result.ShellProfileAnomaly,
				path+": 发现可疑模式 '"+sp.pattern+"' ("+sp.desc+")")
		}
	}

	// 检查文件权限：非 root 可写的全局 profile 是危险的
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0002 != 0 {
		result.ShellProfileAnomaly = append(result.ShellProfileAnomaly,
			path+": world-writable (任何用户可篡改)")
	}
}

// checkDiskSpace 检查输出目录的磁盘空间
func checkDiskSpace(result *model.PreflightResult, outputDir string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(outputDir, &stat); err != nil {
		result.Notes = append(result.Notes, "无法获取输出目录磁盘空间: "+err.Error())
		return
	}
	freeBytes := stat.Bavail * uint64(stat.Bsize)
	freeMB := freeBytes / (1024 * 1024)
	if freeMB < 50 {
		result.Notes = append(result.Notes,
			"输出目录可用空间不足: "+strconv.FormatUint(freeMB, 10)+"MB (建议至少 50MB)")
	}
}
