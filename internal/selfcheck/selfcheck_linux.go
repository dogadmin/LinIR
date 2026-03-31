//go:build linux

package selfcheck

import (
	"bufio"
	"os"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

func platformSelfCheck(result *model.SelfCheckResult) {
	// 1. 检查 /proc/self/exe 是否可读并与 os.Executable() 结果一致
	//
	// 为什么要做这个检查：
	// 如果 /proc/self/exe 的 readlink 结果和 os.Executable() 不一致，
	// 可能说明有人在运行时替换了二进制，或者路径被符号链接劫持。
	checkProcSelfExe(result)

	// 2. 扫描 /proc/self/maps 检查是否有异常的库被加载
	//
	// 为什么要做这个检查：
	// LD_PRELOAD 劫持的典型表现是 maps 中出现了不在标准库路径中的 .so 文件。
	// 即使 LD_PRELOAD 环境变量被清除，maps 中仍会留下痕迹。
	checkProcSelfMaps(result)

	// 3. 检查 /etc/ld.so.preload 是否存在
	//
	// 为什么要做这个检查：
	// /etc/ld.so.preload 是系统级的 preload 配置，比环境变量更隐蔽，
	// 且不会出现在进程的环境变量中。rootkit 常用这个文件实现全局 hook。
	checkLdSoPreload(result)
}

func checkProcSelfExe(result *model.SelfCheckResult) {
	target, err := os.Readlink("/proc/self/exe")
	if err != nil {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"/proc/self/exe 不可读: "+err.Error())
		result.CollectionConfidence = "low"
		return
	}

	// 检查 (deleted) 标记——表示二进制已被删除
	if strings.HasSuffix(target, " (deleted)") {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"自身二进制已被从磁盘删除 (deleted)")
		result.CollectionConfidence = "low"
		return
	}

	// 与 os.Executable() 结果比对
	if result.SelfPath != "" && target != result.SelfPath {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"/proc/self/exe("+target+") 与 os.Executable()("+result.SelfPath+") 路径不一致")
	}
}

func checkProcSelfMaps(result *model.SelfCheckResult) {
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"/proc/self/maps 不可读: "+err.Error())
		return
	}
	defer f.Close()

	// 可疑库路径前缀：不在标准系统库目录中的 .so 文件
	// 标准路径：/lib, /lib64, /usr/lib, /usr/lib64, /usr/local/lib
	standardPrefixes := []string{
		"/lib/", "/lib64/",
		"/usr/lib/", "/usr/lib64/",
		"/usr/local/lib/",
		"/usr/libexec/",
		"[", // 匿名映射 [heap], [stack], [vdso], [vvar] 等
	}

	scanner := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[5]
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}

		// 跳过自身二进制
		if path == result.SelfPath {
			continue
		}

		// 只关心 .so 文件
		if !strings.Contains(path, ".so") {
			continue
		}

		// 去重
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}

		// 检查是否在标准路径中
		isStandard := false
		for _, prefix := range standardPrefixes {
			if strings.HasPrefix(path, prefix) {
				isStandard = true
				break
			}
		}
		if !isStandard {
			result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
				"maps 中存在非标准路径库: "+path)
			// 如果在 /tmp 或 /dev/shm 下，更可疑
			if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/dev/shm/") || strings.HasPrefix(path, "/var/tmp/") {
				result.CollectionConfidence = "low"
			}
		}
	}
}

func checkLdSoPreload(result *model.SelfCheckResult) {
	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return // 文件不存在是正常情况
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return
	}

	// /etc/ld.so.preload 存在且有内容——这很少出现在正常系统中
	result.LDPreloadPresent = true
	result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
		"/etc/ld.so.preload 存在且有内容")

	// 逐行分析
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		result.SelfEnvAnomaly = append(result.SelfEnvAnomaly,
			"/etc/ld.so.preload 条目: "+line)

		// 检查预加载目标是否在可疑路径
		if strings.HasPrefix(line, "/tmp/") || strings.HasPrefix(line, "/dev/shm/") || strings.HasPrefix(line, "/var/tmp/") {
			result.CollectionConfidence = "low"
		} else {
			result.CollectionConfidence = "medium"
		}
	}
}
