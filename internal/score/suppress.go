package score

import (
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// SuppressAction 表示 suppress 决策
type SuppressAction int

const (
	ActionNone      SuppressAction = iota // 正常计分
	ActionDowngrade                       // 降低分值（减半）
	ActionSuppress                        // 完全不计分
)

// 已知合法包管理器/安装器/构建工具进程名
var packageManagers = map[string]bool{
	"apt": true, "apt-get": true, "dpkg": true, "aptitude": true,
	"yum": true, "dnf": true, "rpm": true, "zypper": true,
	"pacman": true, "emerge": true, "apk": true,
	"brew": true, "port": true,
	"pip": true, "pip3": true, "pip2": true,
	"npm": true, "npx": true, "yarn": true, "pnpm": true,
	"go": true, "cargo": true, "rustup": true,
	"gem": true, "bundle": true, "bundler": true,
	"conda": true, "mamba": true,
	"composer": true, "cpan": true,
	"make": true, "cmake": true, "ninja": true,
	"docker": true, "dockerd": true, "containerd": true,
	"snap": true, "flatpak": true,
	"ansible": true, "puppet": true, "chef-client": true, "salt-minion": true,
	"systemd-tmpfiles": true, "tmpfiles.d": true,
	"update-alternatives": true, "unattended-upgrade": true,
}

// 已知合法安装器/部署器路径前缀
var legitimatePathPrefixes = []string{
	"/usr/lib/apt/",
	"/usr/lib/dpkg/",
	"/usr/libexec/",
	"/usr/share/",
	"/opt/homebrew/",
	"/nix/store/",
}

// checkProcessSuppress 检查进程级别的 suppress 条件
func checkProcessSuppress(rule string, p *model.ProcessInfo, ctx *scoringContext) SuppressAction {
	switch rule {
	case "exe_in_tmp":
		return suppressExeInTmp(p, ctx)
	case "exe_deleted":
		return suppressExeDeleted(p, ctx)
	default:
		return ActionNone
	}
}

// checkPersistenceSuppress 检查持久化级别的 suppress 条件
func checkPersistenceSuppress(rule string, item *model.PersistenceItem, ctx *scoringContext) SuppressAction {
	switch rule {
	case "pipe_to_shell":
		return suppressPipeShell(item, ctx)
	default:
		return ActionNone
	}
}

// suppressExeInTmp: 父进程为包管理器/安装器 → downgrade
func suppressExeInTmp(p *model.ProcessInfo, ctx *scoringContext) SuppressAction {
	parent, ok := ctx.pidProc[p.PPID]
	if !ok {
		return ActionNone
	}
	// 父进程是已知包管理器
	if packageManagers[parent.Name] {
		return ActionDowngrade
	}
	// 父进程路径是合法安装器路径
	for _, prefix := range legitimatePathPrefixes {
		if strings.HasPrefix(parent.Exe, prefix) {
			return ActionDowngrade
		}
	}
	return ActionNone
}

// suppressExeDeleted: overlay/container 场景 → downgrade
func suppressExeDeleted(p *model.ProcessInfo, ctx *scoringContext) SuppressAction {
	// 父进程为包管理器（升级替换窗口）→ downgrade
	if parent, ok := ctx.pidProc[p.PPID]; ok {
		if packageManagers[parent.Name] {
			return ActionDowngrade
		}
	}
	// 无网络、无持久化、无 YARA → suppress
	if !ctx.pidNetworked[p.PID] && !hasPersistenceLink(p, ctx) && !ctx.yaraHitPaths[p.Exe] {
		return ActionSuppress
	}
	return ActionNone
}

// suppressPipeShell: 无持久化激活 + 无后续网络 → suppress
func suppressPipeShell(item *model.PersistenceItem, ctx *scoringContext) SuppressAction {
	if !ctx.persistTargetRunning[item.Target] && !ctx.persistTargetNetworked[item.Target] {
		return ActionSuppress
	}
	return ActionNone
}

// hasPersistenceLink 检查进程是否关联到持久化项
func hasPersistenceLink(p *model.ProcessInfo, ctx *scoringContext) bool {
	return ctx.persistTargetRunning[p.Exe]
}

// applyScore 根据 suppress action 决定实际分值
func applyScore(base int, action SuppressAction) int {
	switch action {
	case ActionDowngrade:
		return base / 2
	case ActionSuppress:
		return 0
	default:
		return base
	}
}
