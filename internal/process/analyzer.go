package process

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的进程列表进行二次分析，补充可疑标记。
// 此阶段可以利用全量进程信息做父子链分析等全局性检查。
func Analyze(procs []model.ProcessInfo) {
	if len(procs) == 0 {
		return
	}

	// 构建 PID → ProcessInfo 索引
	pidMap := make(map[int]*model.ProcessInfo, len(procs))
	for i := range procs {
		pidMap[procs[i].PID] = &procs[i]
	}

	for i := range procs {
		p := &procs[i]
		analyzeParentChain(p, pidMap)
		analyzeInterpreterAbuse(p, pidMap)
		analyzeNameDisguise(p)
	}
}

// analyzeParentChain 分析父子进程关系链
func analyzeParentChain(p *model.ProcessInfo, pidMap map[int]*model.ProcessInfo) {
	// 检查异常的父子关系
	parent, hasParent := pidMap[p.PPID]
	if !hasParent || p.PPID <= 1 {
		return
	}

	// Web 服务器 → shell → 其他：典型的 webshell 模式
	webServers := map[string]bool{
		"apache2": true, "httpd": true, "nginx": true, "lighttpd": true,
		"tomcat": true, "java": true, "node": true, "php-fpm": true,
	}
	shells := map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "csh": true, "ksh": true,
	}

	if webServers[parent.Name] && shells[p.Name] {
		addFlag(p, "webserver_spawned_shell")
	}

	// shell → 解释器 + 网络（采集阶段已标记 interpreter，这里检查链）
	if shells[parent.Name] {
		interpreters := map[string]bool{
			"python": true, "python3": true, "perl": true, "ruby": true,
			"php": true, "lua": true, "node": true,
		}
		if interpreters[p.Name] || strings.HasPrefix(p.Name, "python") {
			if len(p.SocketInodes) > 0 {
				addFlag(p, "shell_spawned_interpreter_with_network")
			}
		}
	}

	// sshd → shell 是正常的，但 sshd → 非 shell 可疑
	if parent.Name == "sshd" && !shells[p.Name] && p.Name != "sshd" && p.Name != "sftp-server" {
		addFlag(p, "sshd_spawned_non_shell")
	}

	// cron → 正常，但 cron 子进程联网可疑
	if parent.Name == "cron" || parent.Name == "crond" || parent.Name == "atd" {
		if len(p.SocketInodes) > 0 {
			addFlag(p, "cron_child_with_network")
		}
	}
}

// analyzeInterpreterAbuse 分析解释器滥用模式
func analyzeInterpreterAbuse(p *model.ProcessInfo, pidMap map[int]*model.ProcessInfo) {
	if !hasFlag(p, "interpreter") {
		return
	}

	// 解释器 + 有网络连接 = 可疑
	if len(p.SocketInodes) > 0 {
		addFlag(p, "interpreter_with_network")
	}

	// 解释器从 /tmp 等临时目录执行脚本
	if len(p.Cmdline) >= 2 {
		for _, arg := range p.Cmdline[1:] {
			if strings.HasPrefix(arg, "/tmp/") || strings.HasPrefix(arg, "/var/tmp/") ||
				strings.HasPrefix(arg, "/dev/shm/") {
				addFlag(p, "interpreter_runs_tmp_script")
				break
			}
		}
	}

	// 解释器使用 -c 参数执行内联代码
	for _, arg := range p.Cmdline {
		if arg == "-c" || arg == "-e" {
			addFlag(p, "interpreter_inline_exec")
			break
		}
	}
}

// analyzeNameDisguise 分析进程名伪装
func analyzeNameDisguise(p *model.ProcessInfo) {
	// 进程名中包含大量空格（试图在 ps 输出中隐藏）
	if strings.Contains(p.Name, "  ") {
		addFlag(p, "name_has_spaces")
	}

	// 进程名以 . 或 - 开头（隐藏文件风格）
	if len(p.Name) > 0 && (p.Name[0] == '.' || p.Name[0] == '-') {
		addFlag(p, "name_hidden_prefix")
	}

	// 进程名模仿内核线程（方括号）
	if len(p.Name) > 2 && p.Name[0] == '[' && p.Name[len(p.Name)-1] == ']' {
		// 内核线程的 PPID 通常是 2 (kthreadd)，如果 PPID 不是 2 则可疑
		if p.PPID != 2 && p.PPID != 0 {
			addFlag(p, "fake_kernel_thread")
		}
	}
}

func hasFlag(p *model.ProcessInfo, flag string) bool {
	for _, f := range p.SuspiciousFlags {
		if f == flag {
			return true
		}
	}
	return false
}

func addFlag(p *model.ProcessInfo, flag string) {
	if !hasFlag(p, flag) {
		p.SuspiciousFlags = append(p.SuspiciousFlags, flag)
	}
}
