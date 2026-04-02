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

	// 目标在临时目录——明确可疑
	if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/private/tmp/") ||
		strings.HasPrefix(target, "/var/tmp/") {
		item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
	}

	// 目标不存在——可疑（残留或被删除）
	if target != "" {
		if _, err := os.Stat(target); err != nil {
			item.RiskFlags = append(item.RiskFlags, "target_missing")
		}
	}

	// 用户目录下的 LaunchAgent 伪装 Apple 系统名称——明确可疑
	if scope == "user" {
		if strings.HasPrefix(plist.Label, "com.apple.") {
			item.RiskFlags = append(item.RiskFlags, "impersonates_apple")
		}
	}

	// 仅标记真正高置信度的恶意模式，不标记正常行为：
	// - third_party_run_at_load: 删除（几乎所有第三方 app 都有）
	// - shell_exec: 删除（shell 作为入口是正常的脚本调用方式）
	// - downloads_from_network: 删除（curl/wget 在 args 中很常见）
	// - base64_usage: 删除（合法工具常用）
	// - applescript_exec: 删除（macOS 标准 API）
	// - command_alias_override: 已经在 profile 部分删除

	// 保留：curl/wget 管道到 shell 执行——这才是真正可疑的
	fullArgs := strings.Join(plist.ProgramArguments, " ")
	if (strings.Contains(fullArgs, "curl ") || strings.Contains(fullArgs, "wget ")) &&
		(strings.Contains(fullArgs, "| bash") || strings.Contains(fullArgs, "| sh") ||
			strings.Contains(fullArgs, "|bash") || strings.Contains(fullArgs, "|sh")) {
		item.RiskFlags = append(item.RiskFlags, "pipe_to_shell")
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

	// 仅标记高置信度恶意指标，不标记正常 shell 行为
	// base64/eval/curl/wget/osascript/alias 在正常 profile 中极为常见
	patterns := []struct {
		substr string
		flag   string
	}{
		{"DYLD_INSERT_LIBRARIES", "dyld_inject_export"},
		{"/dev/tcp/", "dev_tcp_reverse_shell"},
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

