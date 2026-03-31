package preflight

import (
	"context"
	"os"
	"strings"

	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
)

// Run 执行采集前的主机环境可信度评估。
//
// 设计原理：在真正开始采集前，先判断目标主机环境是否可信。
// 如果 PATH 被污染、loader 被劫持、关键目录异常，那么后续采集
// 得到的数据可信度就要打折。preflight 的输出直接影响最终的
// host_trust_level 和 collection_confidence。
func Run(ctx context.Context, cfg *config.Config) (*model.PreflightResult, error) {
	result := &model.PreflightResult{
		HostTrustLevel: "high",
	}

	// 1. 检查运行权限
	if os.Geteuid() != 0 {
		result.Notes = append(result.Notes,
			"非 root 运行: 部分 /proc/<pid>/ 数据、socket inode 映射、某些持久化路径可能不可读")
	}

	// 2. PATH 异常检查
	checkPATH(result)

	// 3. 环境变量污染检查（loader 相关 + 通用可疑变量）
	checkLoaderEnv(result)
	checkSuspiciousEnv(result)

	// 4. 平台特定检查
	platformPreflight(result, cfg)

	// 5. 综合评估 trust level
	determineTrustLevel(result)

	return result, nil
}

// checkPATH 检查 PATH 环境变量中的每个目录
func checkPATH(result *model.PreflightResult) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		result.PathAnomaly = append(result.PathAnomaly, "PATH 为空")
		return
	}

	dirs := strings.Split(pathEnv, ":")
	seen := make(map[string]struct{})

	for _, dir := range dirs {
		// 空目录或当前目录 = 路径注入风险
		if dir == "." || dir == "" {
			result.PathAnomaly = append(result.PathAnomaly,
				"PATH 包含相对目录(可被当前目录注入): '"+dir+"'")
			continue
		}

		// 临时目录
		if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") ||
			strings.HasPrefix(dir, "/dev/shm") || strings.HasPrefix(dir, "/dev/mqueue") {
			result.PathAnomaly = append(result.PathAnomaly,
				"PATH 包含临时目录: "+dir)
			continue
		}

		// 用户家目录中的 bin（如果是 root 用户，不应出现普通用户的 bin）
		if os.Geteuid() == 0 && strings.HasPrefix(dir, "/home/") {
			result.PathAnomaly = append(result.PathAnomaly,
				"root PATH 中包含普通用户目录: "+dir)
		}

		// 重复目录
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}

		// 检查目录是否可写（other-writable 目录在 PATH 中是危险的）
		info, err := os.Stat(dir)
		if err != nil {
			// 目录不存在不一定是异常，但记录一下
			continue
		}
		if info.Mode().Perm()&0002 != 0 {
			result.PathAnomaly = append(result.PathAnomaly,
				"PATH 中存在 other-writable 目录: "+dir)
		}
	}
}

// checkLoaderEnv 检查动态链接器相关的危险环境变量
func checkLoaderEnv(result *model.PreflightResult) {
	loaderVars := []string{
		// Linux
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
		"LD_PROFILE", "LD_SHOW_AUXV", "LD_BIND_NOT",
		// macOS
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH", "DYLD_FORCE_FLAT_NAMESPACE", "DYLD_IMAGE_SUFFIX",
	}
	for _, key := range loaderVars {
		if v := os.Getenv(key); v != "" {
			result.LoaderAnomaly = append(result.LoaderAnomaly, key+"="+v)
		}
	}
}

// checkSuspiciousEnv 检查其他可能影响采集行为的环境变量
func checkSuspiciousEnv(result *model.PreflightResult) {
	suspiciousVars := map[string]string{
		"BASH_ENV":   "bash 非交互模式自动加载的脚本",
		"ENV":        "sh 启动时自动加载的脚本",
		"BASH_FUNC_": "bash 导出函数(ShellShock 向量)",
		"PROMPT_COMMAND": "每条命令前自动执行的命令",
	}

	for key, desc := range suspiciousVars {
		if v := os.Getenv(key); v != "" {
			result.EnvAnomaly = append(result.EnvAnomaly,
				key+"="+v+" ("+desc+")")
		}
	}

	// 检查 BASH_FUNC_ 开头的导出函数（ShellShock 变种）
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "BASH_FUNC_") {
			result.EnvAnomaly = append(result.EnvAnomaly,
				"检测到 bash 导出函数: "+strings.SplitN(env, "=", 2)[0])
		}
	}
}

// determineTrustLevel 根据所有发现的异常综合判定主机可信度
func determineTrustLevel(result *model.PreflightResult) {
	// 计算风险权重
	weight := 0

	// VisibilityRisk 最严重——直接影响数据完整性
	weight += len(result.VisibilityRisk) * 30

	// LoaderAnomaly 很严重——可能导致行为被劫持
	weight += len(result.LoaderAnomaly) * 25

	// ShellProfileAnomaly 中等——可能是正常配置也可能是后门
	weight += len(result.ShellProfileAnomaly) * 10

	// PathAnomaly 中等
	weight += len(result.PathAnomaly) * 10

	// EnvAnomaly 较低
	weight += len(result.EnvAnomaly) * 5

	switch {
	case weight >= 30:
		result.HostTrustLevel = "low"
	case weight >= 10:
		result.HostTrustLevel = "medium"
	default:
		result.HostTrustLevel = "high"
	}
}
