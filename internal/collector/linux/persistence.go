//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/sysparse"
)

// PersistenceCollector 通过直接读取文件系统枚举所有持久化机制。
// 严禁调用 systemctl、service、crontab -l 或任何外部命令。
//
// 覆盖范围：
//   - systemd 单元文件 (service/timer)
//   - cron (系统 crontab + 用户 crontab + cron.d + cron.daily/hourly/weekly)
//   - shell profile (/etc/profile, bashrc, zshrc, 用户级)
//   - rc.local
//   - /etc/ld.so.preload
//   - SSH authorized_keys 和 config
type PersistenceCollector struct{}

func NewPersistenceCollector() *PersistenceCollector {
	return &PersistenceCollector{}
}

func (c *PersistenceCollector) CollectPersistence(ctx context.Context) ([]model.PersistenceItem, error) {
	var items []model.PersistenceItem

	// 1. systemd 单元
	items = append(items, c.collectSystemd(ctx)...)

	// 2. cron
	items = append(items, c.collectCron(ctx)...)

	// 3. shell profiles
	items = append(items, c.collectShellProfiles(ctx)...)

	// 4. rc.local
	items = append(items, c.collectRcLocal()...)

	// 5. /etc/ld.so.preload
	items = append(items, c.collectLdSoPreload()...)

	// 6. SSH
	items = append(items, c.collectSSH(ctx)...)

	return items, nil
}

// ========== systemd ==========

func (c *PersistenceCollector) collectSystemd(ctx context.Context) []model.PersistenceItem {
	// systemd 单元搜索路径（按优先级排列）
	unitDirs := []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}

	var items []model.PersistenceItem
	seen := make(map[string]struct{})

	for _, dir := range unitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return items
			default:
			}

			name := entry.Name()
			// 只关注 .service 和 .timer 文件
			if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
				continue
			}

			// 去重：同名单元只取最高优先级的
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}

			path := filepath.Join(dir, name)

			// 解析符号链接——许多 enabled 的 service 是指向实际 unit 的符号链接
			realPath := path
			if target, err := filepath.EvalSymlinks(path); err == nil {
				realPath = target
			}

			unit, err := sysparse.ParseSystemdUnit(realPath)
			if err != nil {
				continue
			}

			item := model.PersistenceItem{
				Type:      "systemd",
				Path:      path,
				Target:    extractExecTarget(unit.ExecStart),
				UserScope: "system",
				Exists:    true,
				Confidence: "high",
				ParsedFields: map[string]string{
					"ExecStart":    unit.ExecStart,
					"ExecStartPre": unit.ExecStartPre,
					"ExecStop":     unit.ExecStop,
					"User":         unit.User,
					"Type":         unit.Type,
					"WantedBy":     unit.WantedBy,
					"Environment":  unit.Environment,
				},
			}

			// 检查 ExecStart 目标是否存在
			if item.Target != "" {
				if _, err := os.Stat(item.Target); err != nil {
					item.RiskFlags = append(item.RiskFlags, "target_missing")
				}
			}

			// 风险标记
			flagSystemdRisks(&item, unit)

			items = append(items, item)
		}
	}
	return items
}

// extractExecTarget 从 ExecStart 值中提取可执行文件路径
// ExecStart 格式可能是: /usr/bin/foo -arg1 -arg2 或 -/usr/bin/foo
func extractExecTarget(execStart string) string {
	if execStart == "" {
		return ""
	}
	// 去掉前缀修饰符 (-/@/+/!)
	s := execStart
	for len(s) > 0 && (s[0] == '-' || s[0] == '@' || s[0] == '+' || s[0] == '!') {
		s = s[1:]
	}
	// 取第一个空格前的部分作为路径
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func flagSystemdRisks(item *model.PersistenceItem, unit *sysparse.SystemdUnit) {
	target := item.Target
	// 目标在临时目录
	if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/var/tmp/") || strings.HasPrefix(target, "/dev/shm/") {
		item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
	}
	// ExecStart 使用 shell 执行
	if strings.Contains(unit.ExecStart, "/bin/sh ") || strings.Contains(unit.ExecStart, "/bin/bash ") {
		item.RiskFlags = append(item.RiskFlags, "shell_exec")
	}
	// 环境变量中设置 LD_PRELOAD
	if strings.Contains(unit.Environment, "LD_PRELOAD") {
		item.RiskFlags = append(item.RiskFlags, "ld_preload_in_env")
	}
	// 用户目录下的 unit 文件（非标准路径下的自定义 service）
	if strings.HasPrefix(item.Path, "/home/") || strings.HasPrefix(target, "/home/") {
		item.RiskFlags = append(item.RiskFlags, "user_home_path")
	}
}

// ========== cron ==========

func (c *PersistenceCollector) collectCron(ctx context.Context) []model.PersistenceItem {
	var items []model.PersistenceItem

	// 系统 crontab（包含 user 字段）
	items = append(items, parseCronFile("/etc/crontab", true, "system")...)

	// /etc/cron.d/ 下的文件（系统格式，包含 user 字段）
	items = append(items, parseCronDir("/etc/cron.d", true, "system")...)

	// cron.daily / cron.hourly / cron.weekly / cron.monthly —— 这些是脚本目录
	cronScriptDirs := []string{
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}
	for _, dir := range cronScriptDirs {
		items = append(items, scanCronScriptDir(dir)...)
	}

	// 用户 crontab —— 不包含 user 字段
	userCronDirs := []string{
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
	}
	for _, dir := range userCronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			cronItems := parseCronFile(path, false, "user")
			// 设置用户名为文件名
			for i := range cronItems {
				if cronItems[i].ParsedFields == nil {
					cronItems[i].ParsedFields = make(map[string]string)
				}
				cronItems[i].ParsedFields["cron_user"] = entry.Name()
			}
			items = append(items, cronItems...)
		}
	}

	return items
}

func parseCronFile(path string, systemFormat bool, scope string) []model.PersistenceItem {
	entries, err := sysparse.ParseCrontab(path, systemFormat)
	if err != nil || len(entries) == 0 {
		return nil
	}

	var items []model.PersistenceItem
	for _, e := range entries {
		item := model.PersistenceItem{
			Type:       "cron",
			Path:       path,
			Target:     extractCronCommand(e.Command),
			UserScope:  scope,
			Exists:     true,
			Confidence: "high",
			ParsedFields: map[string]string{
				"schedule": strings.Join([]string{e.Minute, e.Hour, e.Day, e.Month, e.Weekday}, " "),
				"command":  e.Command,
				"user":     e.User,
				"raw":      e.Raw,
			},
		}
		flagCronRisks(&item, e)
		items = append(items, item)
	}
	return items
}

func parseCronDir(dir string, systemFormat bool, scope string) []model.PersistenceItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var items []model.PersistenceItem
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		items = append(items, parseCronFile(path, systemFormat, scope)...)
	}
	return items
}

func scanCronScriptDir(dir string) []model.PersistenceItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var items []model.PersistenceItem
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		item := model.PersistenceItem{
			Type:       "cron",
			Path:       path,
			Target:     path,
			UserScope:  "system",
			Exists:     true,
			Confidence: "high",
			ParsedFields: map[string]string{
				"schedule": filepath.Base(dir), // cron.daily / cron.hourly 等
			},
		}
		// 检查脚本是否指向临时目录
		if target, err := filepath.EvalSymlinks(path); err == nil && target != path {
			item.Target = target
			item.ParsedFields["symlink_target"] = target
		}
		flagScriptRisks(&item, path)
		items = append(items, item)
	}
	return items
}

// extractCronCommand 提取 cron 命令中的第一个可执行文件路径
func extractCronCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	// 跳过常见的环境变量前缀
	for strings.Contains(cmd, "=") && !strings.HasPrefix(cmd, "/") {
		fields := strings.Fields(cmd)
		if len(fields) <= 1 {
			break
		}
		if !strings.Contains(fields[0], "=") {
			break
		}
		cmd = strings.Join(fields[1:], " ")
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func flagCronRisks(item *model.PersistenceItem, e sysparse.CrontabEntry) {
	cmd := e.Command
	target := item.Target

	if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/var/tmp/") || strings.HasPrefix(target, "/dev/shm/") {
		item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
	}
	if strings.Contains(cmd, "curl ") || strings.Contains(cmd, "wget ") {
		item.RiskFlags = append(item.RiskFlags, "downloads_from_network")
	}
	if strings.Contains(cmd, "| bash") || strings.Contains(cmd, "| sh") || strings.Contains(cmd, "|bash") || strings.Contains(cmd, "|sh") {
		item.RiskFlags = append(item.RiskFlags, "pipe_to_shell")
	}
	if strings.Contains(cmd, "base64") {
		item.RiskFlags = append(item.RiskFlags, "base64_usage")
	}
	if strings.Contains(cmd, "/dev/tcp/") {
		item.RiskFlags = append(item.RiskFlags, "dev_tcp_reverse_shell")
	}
	if e.Minute == "@reboot" {
		item.RiskFlags = append(item.RiskFlags, "runs_at_reboot")
	}
}

func flagScriptRisks(item *model.PersistenceItem, path string) {
	if strings.HasPrefix(item.Target, "/tmp/") || strings.HasPrefix(item.Target, "/dev/shm/") {
		item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0002 != 0 {
		item.RiskFlags = append(item.RiskFlags, "world_writable")
	}
}

// ========== shell profiles ==========

func (c *PersistenceCollector) collectShellProfiles(ctx context.Context) []model.PersistenceItem {
	systemProfiles := []string{
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/bashrc",
		"/etc/zshrc",
		"/etc/zshenv",
	}

	var items []model.PersistenceItem

	// 系统级 profile
	for _, path := range systemProfiles {
		if item := checkProfileFile(path, "system"); item != nil {
			items = append(items, *item)
		}
	}

	// /etc/profile.d/ 目录
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join("/etc/profile.d", entry.Name())
			if item := checkProfileFile(path, "system"); item != nil {
				items = append(items, *item)
			}
		}
	}

	// 用户级 profile —— 遍历 /home 下所有用户
	if entries, err := os.ReadDir("/home"); err == nil {
		userProfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv"}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			for _, pf := range userProfiles {
				path := filepath.Join("/home", entry.Name(), pf)
				if item := checkProfileFile(path, "user"); item != nil {
					items = append(items, *item)
				}
			}
		}
	}

	// root 用户 profile
	rootProfiles := []string{"/root/.bashrc", "/root/.bash_profile", "/root/.profile", "/root/.zshrc"}
	for _, path := range rootProfiles {
		if item := checkProfileFile(path, "system"); item != nil {
			items = append(items, *item)
		}
	}

	return items
}

func checkProfileFile(path, scope string) *model.PersistenceItem {
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

	// 扫描可疑模式
	patterns := []struct {
		substr string
		flag   string
	}{
		{"export LD_PRELOAD", "ld_preload_export"},
		{"export DYLD_INSERT", "dyld_inject_export"},
		{"/dev/tcp/", "dev_tcp_reverse_shell"},
		{"base64 -d", "base64_decode"},
		{"base64 --decode", "base64_decode"},
		{"eval ", "eval_usage"},
		{"curl ", "network_download"},
		{"wget ", "network_download"},
		{"python -c", "script_oneliner"},
		{"perl -e", "script_oneliner"},
		{"alias ps=", "command_alias_override"},
		{"alias ls=", "command_alias_override"},
		{"alias netstat=", "command_alias_override"},
		{"alias ss=", "command_alias_override"},
	}

	for _, p := range patterns {
		if strings.Contains(content, p.substr) {
			item.RiskFlags = append(item.RiskFlags, p.flag)
		}
	}

	// 检查文件权限
	info, err := os.Stat(path)
	if err == nil && info.Mode().Perm()&0002 != 0 {
		item.RiskFlags = append(item.RiskFlags, "world_writable")
	}

	// 如果没有任何风险标记且是用户级的 profile，跳过输出（减少噪音）
	if len(item.RiskFlags) == 0 && scope == "user" {
		return nil
	}

	return item
}

// ========== rc.local ==========

func (c *PersistenceCollector) collectRcLocal() []model.PersistenceItem {
	path := "/etc/rc.local"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	item := model.PersistenceItem{
		Type:       "rc_local",
		Path:       path,
		UserScope:  "system",
		Exists:     true,
		Confidence: "high",
	}

	// 检查是否有实际内容（不只是注释和空行）
	hasContent := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
			continue
		}
		hasContent = true
		item.Target = line // 记录第一行有效命令
		break
	}

	if !hasContent {
		return nil
	}

	// 检查可执行权限
	info, err := os.Stat(path)
	if err == nil && info.Mode().Perm()&0111 != 0 {
		item.RiskFlags = append(item.RiskFlags, "executable")
	}

	return []model.PersistenceItem{item}
}

// ========== /etc/ld.so.preload ==========

func (c *PersistenceCollector) collectLdSoPreload() []model.PersistenceItem {
	path := "/etc/ld.so.preload"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil
	}

	var items []model.PersistenceItem
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		item := model.PersistenceItem{
			Type:       "ld_preload",
			Path:       path,
			Target:     line,
			UserScope:  "system",
			Confidence: "high",
			RiskFlags:  []string{"system_wide_preload"},
		}
		// 检查目标 so 是否存在
		if _, err := os.Stat(line); err != nil {
			item.RiskFlags = append(item.RiskFlags, "target_missing")
			item.Exists = false
		} else {
			item.Exists = true
			// 目标在临时目录
			if strings.HasPrefix(line, "/tmp/") || strings.HasPrefix(line, "/dev/shm/") || strings.HasPrefix(line, "/var/tmp/") {
				item.RiskFlags = append(item.RiskFlags, "target_in_tmp")
			}
		}
		items = append(items, item)
	}
	return items
}

// ========== SSH ==========

func (c *PersistenceCollector) collectSSH(ctx context.Context) []model.PersistenceItem {
	var items []model.PersistenceItem

	// 系统级 SSH 配置
	if item := checkSSHFile("/etc/ssh/sshd_config", "system"); item != nil {
		items = append(items, *item)
	}

	// root authorized_keys
	rootSSHFiles := []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2", "/root/.ssh/config"}
	for _, path := range rootSSHFiles {
		if item := checkSSHAuthKeys(path, "system"); item != nil {
			items = append(items, *item)
		}
	}

	// 用户级 authorized_keys
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			sshFiles := []string{
				filepath.Join("/home", entry.Name(), ".ssh", "authorized_keys"),
				filepath.Join("/home", entry.Name(), ".ssh", "authorized_keys2"),
				filepath.Join("/home", entry.Name(), ".ssh", "config"),
			}
			for _, path := range sshFiles {
				if item := checkSSHAuthKeys(path, "user"); item != nil {
					items = append(items, *item)
				}
			}
		}
	}

	return items
}

func checkSSHFile(path, scope string) *model.PersistenceItem {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	item := &model.PersistenceItem{
		Type:       "ssh",
		Path:       path,
		UserScope:  scope,
		Exists:     true,
		Confidence: "high",
	}
	if info.Mode().Perm()&0077 != 0 {
		item.RiskFlags = append(item.RiskFlags, "loose_permissions")
	}
	return item
}

func checkSSHAuthKeys(path, scope string) *model.PersistenceItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	item := &model.PersistenceItem{
		Type:       "ssh",
		Path:       path,
		UserScope:  scope,
		Exists:     true,
		Confidence: "high",
		ParsedFields: map[string]string{},
	}

	// 统计 key 数量
	keyCount := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyCount++

		// 检查 command= 选项（可被滥用执行任意命令）
		if strings.HasPrefix(line, "command=") || strings.Contains(line, ",command=") {
			item.RiskFlags = append(item.RiskFlags, "forced_command")
		}
		// 检查 no-pty 等限制选项被移除
		if strings.HasPrefix(line, "no-") {
			// 这实际上是安全限制，不标记
		}
	}

	item.ParsedFields["key_count"] = itoa(keyCount)

	// 文件权限检查
	info, err := os.Stat(path)
	if err == nil && info.Mode().Perm()&0077 != 0 {
		item.RiskFlags = append(item.RiskFlags, "loose_permissions")
	}

	return item
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
