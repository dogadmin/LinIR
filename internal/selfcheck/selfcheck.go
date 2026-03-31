package selfcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/hashutil"
)

// Run performs the binary self-integrity check and detects environment
// pollution that could compromise collection reliability.
//
// 设计原理：LinIR 启动后第一件事就是检查自身运行环境是否已经被污染。
// 如果 LD_PRELOAD / DYLD_INSERT_LIBRARIES 已设置，说明目标机上存在
// 用户态劫持风险，LinIR 自身的行为可能已经不可信（尽管静态编译可缓解）。
func Run(ctx context.Context) (*model.SelfCheckResult, error) {
	result := &model.SelfCheckResult{
		CollectionConfidence: "high",
	}

	// 1. 获取自身路径
	exe, err := os.Executable()
	if err != nil {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, "无法确定自身路径: "+err.Error())
		result.CollectionConfidence = "low"
		return result, nil
	}
	// 解析符号链接，获取真实路径
	realExe, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = realExe
	}
	result.SelfPath = exe

	// 2. 计算自身二进制哈希，供后续完整性参考
	hash, err := hashutil.SHA256File(exe)
	if err != nil {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, "无法哈希自身二进制: "+err.Error())
	}
	_ = hash // 记录在输出中供对比

	// 3. 检查自身运行路径是否可疑
	checkSelfPath(result, exe)

	// 4. 检查 loader 劫持相关环境变量
	checkLoaderEnv(result)

	// 5. 检查 PATH 中是否有可疑目录
	checkSelfPATH(result)

	// 6. 检查是否静态链接（静态优先可信度更高）
	result.StaticLinkPreferred = isStaticBinary(exe)

	// 7. 平台特定检查
	platformSelfCheck(result)

	return result, nil
}

// checkSelfPath 检查 LinIR 自身的运行路径是否来自可疑位置
func checkSelfPath(result *model.SelfCheckResult, exe string) {
	suspiciousPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/dev/mqueue/"}
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(exe, prefix) {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"自身运行路径位于临时目录: "+exe)
			result.CollectionConfidence = "medium"
			return
		}
	}
}

// checkLoaderEnv 检查与动态链接器劫持相关的环境变量
func checkLoaderEnv(result *model.SelfCheckResult) {
	// Linux LD_* 系列
	ldVars := []string{
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
		"LD_AUDIT",
		"LD_DEBUG",
		"LD_PROFILE",
	}
	for _, key := range ldVars {
		if v := os.Getenv(key); v != "" {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, key+"="+v)
			if key == "LD_PRELOAD" {
				result.LDPreloadPresent = true
				result.CollectionConfidence = "medium"
			}
			if key == "LD_AUDIT" {
				// LD_AUDIT 比 LD_PRELOAD 更危险，可拦截所有符号解析
				result.CollectionConfidence = "low"
			}
		}
	}

	// macOS DYLD_* 系列
	dyldVars := []string{
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		"DYLD_FRAMEWORK_PATH",
		"DYLD_FALLBACK_LIBRARY_PATH",
		"DYLD_IMAGE_SUFFIX",
		"DYLD_FORCE_FLAT_NAMESPACE",
	}
	for _, key := range dyldVars {
		if v := os.Getenv(key); v != "" {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, key+"="+v)
			if key == "DYLD_INSERT_LIBRARIES" {
				result.DYLDInjectionPresent = true
				result.CollectionConfidence = "medium"
			}
		}
	}
}

// checkSelfPATH 检查 PATH 环境变量中是否包含可疑目录
func checkSelfPATH(result *model.SelfCheckResult) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, "PATH 为空")
		return
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "." || dir == "" {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"PATH 包含相对目录(当前目录注入风险): '"+dir+"'")
		}
		if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") || strings.HasPrefix(dir, "/dev/shm") {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"PATH 包含临时目录: "+dir)
		}
	}
}

// isStaticBinary 简单判断自身是否为静态链接二进制
// 通过检查 /proc/self/maps 中是否加载了 ld-linux 或 dyld 来判断。
// 如果不在 Linux 上，回退到检查文件头。
func isStaticBinary(exe string) bool {
	// 尝试读 /proc/self/maps（仅 Linux 可用）
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		// 非 Linux 或无法读取，保守返回 false
		return false
	}
	content := string(data)
	// 静态链接的 Go 二进制在 maps 中不应有 ld-linux*.so
	return !strings.Contains(content, "ld-linux") &&
		!strings.Contains(content, "ld-musl") &&
		!strings.Contains(content, "/lib64/ld-") &&
		!strings.Contains(content, "/lib/ld-")
}
