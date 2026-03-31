package process

import (
	"github.com/dogadmin/LinIR/internal/model"
)

// Analyze 对采集后的进程列表做二次分析。
// 设计原则：只标记需要安全人员关注的异常组合行为，
// 不标记单独存在的正常系统行为（如 bash 运行、python 联网）。
func Analyze(procs []model.ProcessInfo) {
	if len(procs) == 0 {
		return
	}

	pidMap := make(map[int]*model.ProcessInfo, len(procs))
	for i := range procs {
		pidMap[procs[i].PID] = &procs[i]
	}

	for i := range procs {
		p := &procs[i]
		analyzeWebshellChain(p, pidMap)
		analyzeNameDisguise(p)
	}
}

// analyzeWebshellChain 检测 webshell 模式：Web 服务器直接派生 shell
// 这是最明确的入侵指标之一。
func analyzeWebshellChain(p *model.ProcessInfo, pidMap map[int]*model.ProcessInfo) {
	parent, hasParent := pidMap[p.PPID]
	if !hasParent || p.PPID <= 1 {
		return
	}

	webServers := map[string]bool{
		"apache2": true, "httpd": true, "nginx": true, "lighttpd": true,
		"tomcat": true, "php-fpm": true,
	}
	shells := map[string]bool{
		"bash": true, "sh": true, "dash": true, "zsh": true, "csh": true, "ksh": true,
	}

	// Web 服务器 → shell：典型 webshell
	if webServers[parent.Name] && shells[p.Name] {
		addFlag(p, "webserver_spawned_shell")
	}
}

// analyzeNameDisguise 检测进程名伪装
func analyzeNameDisguise(p *model.ProcessInfo) {
	// 伪装内核线程：名字用方括号但 PPID 不是 kthreadd(2)
	if len(p.Name) > 2 && p.Name[0] == '[' && p.Name[len(p.Name)-1] == ']' {
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

