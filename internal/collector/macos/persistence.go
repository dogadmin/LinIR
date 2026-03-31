//go:build darwin

package macos

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/plistutil"
)

// PersistenceCollector 通过直接解析 plist 文件和文件系统枚举 macOS 持久化机制。
// 严禁调用 launchctl 或任何外部命令。
//
// 覆盖范围：
//   - LaunchDaemons (系统级守护进程)
//   - LaunchAgents (用户级和系统级代理)
//   - shell profile (.bashrc, .zshrc 等)
//   - Login Items 相关路径
//   - SSH authorized_keys
type PersistenceCollector struct{}

func NewPersistenceCollector() *PersistenceCollector {
	return &PersistenceCollector{}
}

func (c *PersistenceCollector) CollectPersistence(ctx context.Context) ([]model.PersistenceItem, error) {
	var items []model.PersistenceItem

	// 1. LaunchDaemons / LaunchAgents
	items = append(items, c.collectLaunchItems(ctx)...)

	// 2. shell profiles
	items = append(items, c.collectShellProfiles()...)

	// 3. SSH authorized_keys
	items = append(items, c.collectSSH()...)

	return items, nil
}

// ========== LaunchDaemons / LaunchAgents ==========

func (c *PersistenceCollector) collectLaunchItems(ctx context.Context) []model.PersistenceItem {
	// 系统级目录
	dirs := []struct {
		path  string
		scope string
	}{
		{"/System/Library/LaunchDaemons", "system"},
		{"/Library/LaunchDaemons", "system"},
		{"/System/Library/LaunchAgents", "system"},
		{"/Library/LaunchAgents", "system"},
	}

	// 用户级目录
	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, struct {
			path  string
			scope string
		}{filepath.Join(home, "Library", "LaunchAgents"), "user"})
	}

	// 遍历所有用户的 LaunchAgents
	userDirs, _ := os.ReadDir("/Users")
	for _, ud := range userDirs {
		if !ud.IsDir() || ud.Name() == "Shared" {
			continue
		}
		userLA := filepath.Join("/Users", ud.Name(), "Library", "LaunchAgents")
		dirs = append(dirs, struct {
			path  string
			scope string
		}{userLA, "user"})
	}

	var items []model.PersistenceItem
	for _, dir := range dirs {
		select {
		case <-ctx.Done():
			return items
		default:
		}

		entries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir.path, entry.Name())
			item := parseLaunchPlist(path, dir.scope)
			if item != nil {
				items = append(items, *item)
			}
		}
	}

	return items
}

func parseLaunchPlist(path, scope string) *model.PersistenceItem {
	plist, err := plistutil.ParseLaunchPlist(path)
	if err != nil {
		// plist 解析失败本身也值得记录
		return &model.PersistenceItem{
			Type:       "launchd",
			Path:       path,
			UserScope:  scope,
			Exists:     true,
			Confidence: "low",
			RiskFlags:  []string{"plist_parse_failed"},
		}
	}

	command := plistutil.GetCommand(plist)

	item := &model.PersistenceItem{
		Type:      "launchd",
		Path:      path,
		Target:    command,
		UserScope: scope,
		Exists:    true,
		Confidence: "high",
		ParsedFields: map[string]string{
			"Label": plist.Label,
		},
	}

	if plist.Program != "" {
		item.ParsedFields["Program"] = plist.Program
	}
	if len(plist.ProgramArguments) > 0 {
		item.ParsedFields["ProgramArguments"] = strings.Join(plist.ProgramArguments, " ")
	}
	if plist.RunAtLoad {
		item.ParsedFields["RunAtLoad"] = "true"
	}
	if plist.UserName != "" {
		item.ParsedFields["UserName"] = plist.UserName
	}
	if plist.Disabled {
		item.ParsedFields["Disabled"] = "true"
	}
	if len(plist.WatchPaths) > 0 {
		item.ParsedFields["WatchPaths"] = strings.Join(plist.WatchPaths, ", ")
	}

	// 风险标记
	flagLaunchRisks(item, plist, scope)

	return item
}

func flagLaunchRisks(item *model.PersistenceItem, plist *plistutil.LaunchItem, scope string) {
	target := item.Target

	// 目标在临时目录
	if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/private/tmp/") ||
		strings.HasPrefix(target, "/var/tmp/") {
		item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
	}

	// 目标不存在
	if target != "" {
		if _, err := os.Stat(target); err != nil {
			item.RiskFlags = append(item.RiskFlags, "target_missing")
		}
	}

	// RunAtLoad 且在非 Apple 目录（第三方自启动）
	if plist.RunAtLoad && !strings.HasPrefix(item.Path, "/System/Library/") {
		item.RiskFlags = append(item.RiskFlags, "third_party_run_at_load")
	}

	// 用户目录下的 LaunchAgent 伪装系统名称
	if scope == "user" {
		if strings.HasPrefix(plist.Label, "com.apple.") {
			item.RiskFlags = append(item.RiskFlags, "impersonates_apple")
		}
	}

	// 命令参数中的可疑模式
	fullArgs := strings.Join(plist.ProgramArguments, " ")
	if strings.Contains(fullArgs, "curl ") || strings.Contains(fullArgs, "wget ") {
		item.RiskFlags = append(item.RiskFlags, "downloads_from_network")
	}
	if strings.Contains(fullArgs, "base64") {
		item.RiskFlags = append(item.RiskFlags, "base64_usage")
	}
	if strings.Contains(fullArgs, "osascript") {
		item.RiskFlags = append(item.RiskFlags, "applescript_exec")
	}

	// 使用 bash/sh -c 执行（可能是为了执行复杂命令链）
	if target == "/bin/bash" || target == "/bin/sh" || target == "/bin/zsh" {
		item.RiskFlags = append(item.RiskFlags, "shell_exec")
	}
}

// ========== shell profiles ==========

func (c *PersistenceCollector) collectShellProfiles() []model.PersistenceItem {
	var items []model.PersistenceItem

	// 系统级
	systemProfiles := []string{"/etc/profile", "/etc/bashrc", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv"}
	for _, path := range systemProfiles {
		if item := checkMacProfileFile(path, "system"); item != nil {
			items = append(items, *item)
		}
	}

	// 用户级
	home, err := os.UserHomeDir()
	if err == nil {
		userProfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv"}
		for _, pf := range userProfiles {
			path := filepath.Join(home, pf)
			if item := checkMacProfileFile(path, "user"); item != nil {
				items = append(items, *item)
			}
		}
	}

	return items
}

func checkMacProfileFile(path, scope string) *model.PersistenceItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	item := &model.PersistenceItem{
		Type:       "shell_profile",
		Path:       path,
		UserScope:  scope,
		Exists:     true,
		Confidence: "high",
	}

	patterns := []struct {
		substr string
		flag   string
	}{
		{"DYLD_INSERT_LIBRARIES", "dyld_inject_export"},
		{"DYLD_LIBRARY_PATH", "dyld_path_override"},
		{"/dev/tcp/", "dev_tcp_reverse_shell"},
		{"base64", "base64_usage"},
		{"eval ", "eval_usage"},
		{"curl ", "network_download"},
		{"wget ", "network_download"},
		{"osascript", "applescript_exec"},
		{"alias ps=", "command_alias_override"},
		{"alias ls=", "command_alias_override"},
	}

	for _, p := range patterns {
		if strings.Contains(content, p.substr) {
			item.RiskFlags = append(item.RiskFlags, p.flag)
		}
	}

	if len(item.RiskFlags) == 0 && scope == "user" {
		return nil
	}
	return item
}

// ========== SSH ==========

func (c *PersistenceCollector) collectSSH() []model.PersistenceItem {
	var items []model.PersistenceItem

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	sshFiles := []string{
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".ssh", "authorized_keys2"),
	}

	for _, path := range sshFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		keyCount := 0
		hasForced := false
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			keyCount++
			if strings.HasPrefix(line, "command=") || strings.Contains(line, ",command=") {
				hasForced = true
			}
		}

		item := model.PersistenceItem{
			Type:       "ssh",
			Path:       path,
			UserScope:  "user",
			Exists:     true,
			Confidence: "high",
			ParsedFields: map[string]string{
				"key_count": strconv.Itoa(keyCount),
			},
		}
		if hasForced {
			item.RiskFlags = append(item.RiskFlags, "forced_command")
		}

		info, err := os.Stat(path)
		if err == nil && info.Mode().Perm()&0077 != 0 {
			item.RiskFlags = append(item.RiskFlags, "loose_permissions")
		}

		items = append(items, item)
	}

	return items
}

