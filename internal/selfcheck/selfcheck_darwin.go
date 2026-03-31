//go:build darwin

package selfcheck

import (
	"os"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

func platformSelfCheck(result *model.SelfCheckResult) {
	// 1. 全面扫描 DYLD_* 环境变量
	//
	// 为什么要做这个检查：
	// macOS 上 DYLD_INSERT_LIBRARIES 是最常见的注入向量，类似 Linux 的 LD_PRELOAD。
	// 但还有其他 DYLD_* 变量也可以影响动态链接行为。
	// 注意：SIP 启用时系统会自动清除这些变量给受保护的二进制，
	// 但 LinIR 自身不一定受 SIP 保护。
	checkDYLDVars(result)

	// 2. 检查自身路径是否可疑
	checkDarwinSelfPath(result)

	// 3. 记录 macOS 特有的能力限制
	// 即使环境看起来干净，SIP/TCC 也可能限制我们的可见性，
	// 这不是异常而是预期行为，需要在输出中明确区分。
	checkDarwinCapabilityLimits(result)
}

func checkDYLDVars(result *model.SelfCheckResult) {
	// 完整的 DYLD_* 危险变量列表
	dangerousVars := map[string]string{
		"DYLD_INSERT_LIBRARIES":       "动态库注入，类似 LD_PRELOAD",
		"DYLD_FORCE_FLAT_NAMESPACE":   "强制平坦命名空间，可影响符号解析",
		"DYLD_LIBRARY_PATH":           "覆盖库搜索路径",
		"DYLD_FRAMEWORK_PATH":         "覆盖 framework 搜索路径",
		"DYLD_FALLBACK_LIBRARY_PATH":  "备选库搜索路径",
		"DYLD_FALLBACK_FRAMEWORK_PATH": "备选 framework 搜索路径",
		"DYLD_IMAGE_SUFFIX":           "强制加载 _debug/_profile 后缀库",
		"DYLD_PRINT_LIBRARIES":        "调试: 打印加载的库",
		"DYLD_PRINT_APIS":             "调试: 打印 dyld API 调用",
	}

	for key, desc := range dangerousVars {
		if v := os.Getenv(key); v != "" {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				key+"="+v+" ("+desc+")")
			if key == "DYLD_INSERT_LIBRARIES" {
				result.DYLDInjectionPresent = true
				result.CollectionConfidence = "low"
			} else if key == "DYLD_FORCE_FLAT_NAMESPACE" || key == "DYLD_LIBRARY_PATH" {
				if result.CollectionConfidence == "high" {
					result.CollectionConfidence = "medium"
				}
			}
		}
	}

	// 也扫描所有以 DYLD_ 开头的未知变量
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "DYLD_") {
			continue
		}
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := parts[0]
		if _, known := dangerousVars[key]; !known {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"未知 DYLD 变量: "+env)
		}
	}
}

func checkDarwinSelfPath(result *model.SelfCheckResult) {
	// macOS 上可疑路径
	suspiciousPrefixes := []string{
		"/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/",
	}
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(result.SelfPath, prefix) {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"自身运行路径位于临时目录: "+result.SelfPath)
			if result.CollectionConfidence == "high" {
				result.CollectionConfidence = "medium"
			}
			return
		}
	}
}

func checkDarwinCapabilityLimits(result *model.SelfCheckResult) {
	// 检查是否以 root 运行
	if os.Geteuid() != 0 {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"非 root 运行: macOS 上部分进程信息和持久化路径可能不可访问(这是 SIP/TCC 的预期行为而非异常)")
	}
}
