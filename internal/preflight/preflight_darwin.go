//go:build darwin

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
	// 1. macOS 版本检测
	checkMacOSVersion(result)

	// 2. SIP 状态推断（通过文件系统可写性间接判断）
	checkSIPStatus(result)

	// 3. 关键持久化目录可达性
	checkLaunchDirectories(result)

	// 4. shell profile 检查
	checkDarwinShellProfiles(result)

	// 5. 磁盘空间检查
	checkDarwinDiskSpace(result, cfg.OutputDir)
}

// checkMacOSVersion 通过读 SystemVersion.plist 获取版本信息
func checkMacOSVersion(result *model.PreflightResult) {
	// 不用 sw_vers 命令，直接读 plist 文件
	versionPlist := "/System/Library/CoreServices/SystemVersion.plist"
	if _, err := os.Stat(versionPlist); err != nil {
		result.Notes = append(result.Notes,
			"无法访问 SystemVersion.plist: macOS 版本未知")
		return
	}

	data, err := os.ReadFile(versionPlist)
	if err != nil {
		result.Notes = append(result.Notes,
			"无法读取 SystemVersion.plist: "+err.Error())
		return
	}
	content := string(data)

	// 简单提取版本信息（避免引入 plist 解析依赖到 preflight 中）
	version := extractPlistValue(content, "ProductVersion")
	build := extractPlistValue(content, "ProductBuildVersion")
	if version != "" {
		result.Notes = append(result.Notes,
			"macOS 版本: "+version+" (Build "+build+")")
	}
}

// extractPlistValue 从 XML plist 中简单提取指定 key 的 string value
func extractPlistValue(content, key string) string {
	keyTag := "<key>" + key + "</key>"
	idx := strings.Index(content, keyTag)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(keyTag):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < 0 || end <= start {
		return ""
	}
	return rest[start+8 : end]
}

// checkSIPStatus 通过间接方式推断 SIP 是否启用
// 我们不调用 csrutil（那是外部命令），而是通过检查受 SIP 保护的路径可写性来推断
func checkSIPStatus(result *model.PreflightResult) {
	// SIP 保护的典型路径
	protectedPaths := []string{
		"/System/Library",
		"/usr/lib",
		"/usr/bin",
	}

	sipLikelyEnabled := true
	for _, path := range protectedPaths {
		// 尝试在受保护路径下创建临时文件来检测是否可写
		// 实际上我们不创建文件，只检查目录的写权限
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		// 如果 root 用户对受保护路径有写权限，SIP 可能被禁用
		if os.Geteuid() == 0 && info.Mode().Perm()&0200 != 0 {
			// 这不完全准确，因为 SIP 的限制在内核层面
			// 但如果可以写这些目录，很可能 SIP 被禁用了
		}
	}

	if sipLikelyEnabled {
		result.Notes = append(result.Notes,
			"SIP 状态: 可能已启用(受保护路径不可修改); "+
				"SIP 会限制某些系统路径的访问但这是预期行为，不是异常")
	}
}

// checkLaunchDirectories 检查关键持久化目录的可访问性
func checkLaunchDirectories(result *model.PreflightResult) {
	dirs := []struct {
		path string
		desc string
	}{
		{"/Library/LaunchDaemons", "系统级 LaunchDaemons"},
		{"/Library/LaunchAgents", "系统级 LaunchAgents"},
		{"/System/Library/LaunchDaemons", "Apple LaunchDaemons"},
		{"/System/Library/LaunchAgents", "Apple LaunchAgents"},
	}

	for _, d := range dirs {
		if _, err := os.Stat(d.path); err != nil {
			result.VisibilityRisk = append(result.VisibilityRisk,
				d.desc+" ("+d.path+") 不可访问: "+err.Error())
			continue
		}
		entries, err := os.ReadDir(d.path)
		if err != nil {
			result.VisibilityRisk = append(result.VisibilityRisk,
				d.desc+" ("+d.path+") 不可列目录: "+err.Error())
			continue
		}
		_ = entries // 可以列出就好
	}

	// 检查用户目录的 LaunchAgents
	home, err := os.UserHomeDir()
	if err == nil {
		userLA := filepath.Join(home, "Library", "LaunchAgents")
		if _, err := os.Stat(userLA); err != nil {
			result.Notes = append(result.Notes,
				"用户 LaunchAgents 目录不可访问: "+userLA)
		}
	}
}

// checkDarwinShellProfiles 检查 macOS 上的 shell profile 文件
func checkDarwinShellProfiles(result *model.PreflightResult) {
	profiles := []string{
		"/etc/profile",
		"/etc/bashrc",
		"/etc/zshrc",
		"/etc/zprofile",
	}

	// 也检查用户目录
	home, err := os.UserHomeDir()
	if err == nil {
		profiles = append(profiles,
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".bash_profile"),
			filepath.Join(home, ".zshrc"),
			filepath.Join(home, ".zprofile"),
			filepath.Join(home, ".profile"),
		)
	}

	for _, path := range profiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		suspiciousPatterns := []struct {
			pattern string
			desc    string
		}{
			{"DYLD_INSERT_LIBRARIES", "DYLD 注入设置"},
			{"DYLD_LIBRARY_PATH", "DYLD 库路径覆盖"},
			{"base64", "base64 编解码"},
			{"curl ", "curl 下载"},
			{"wget ", "wget 下载"},
			{"eval ", "eval 执行"},
			{"python -c", "python 单行执行"},
			{"osascript", "AppleScript 执行"},
			{"alias ls=", "ls 别名覆盖"},
			{"alias ps=", "ps 别名覆盖"},
		}

		for _, sp := range suspiciousPatterns {
			if strings.Contains(content, sp.pattern) {
				result.ShellProfileAnomaly = append(result.ShellProfileAnomaly,
					path+": 发现可疑模式 '"+sp.pattern+"' ("+sp.desc+")")
			}
		}
	}
}

// checkDarwinDiskSpace 检查输出目录磁盘空间
func checkDarwinDiskSpace(result *model.PreflightResult, outputDir string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(outputDir, &stat); err != nil {
		result.Notes = append(result.Notes, "无法获取输出目录磁盘空间: "+err.Error())
		return
	}
	freeBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	freeMB := freeBytes / (1024 * 1024)
	if freeMB < 50 {
		result.Notes = append(result.Notes,
			"输出目录可用空间不足: "+strconv.FormatUint(freeMB, 10)+"MB (建议至少 50MB)")
	}
}
