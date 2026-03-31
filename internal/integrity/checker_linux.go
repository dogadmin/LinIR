//go:build linux

package integrity

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// checkLinuxKernel 执行 Linux 特有的内核级完整性检查
//
// 检查内容：
//   1. /proc/modules vs /sys/module 对比
//      - /proc/modules 是内核通过 proc 接口暴露的已加载模块列表
//      - /sys/module 是 sysfs 中的模块目录
//      - 如果一个模块在 /sys/module 中存在但不在 /proc/modules 中，
//        可能是 rootkit 在 proc 层面隐藏了自己
//      - 反过来，如果在 /proc/modules 中但不在 /sys/module 中，也异常
//
//   2. /proc/sys/kernel/tainted — 内核污染标志位
//      非零值说明内核加载了非标准模块或发生了异常事件
func platformKernelCheck(ctx context.Context, ir *model.IntegrityResult) {
	checkKernelTaint(ir)
	checkModuleVisibility(ir)
}

// checkKernelTaint 读取内核 taint 状态
func checkKernelTaint(ir *model.IntegrityResult) {
	data, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		ir.VisibilityAnomalies = append(ir.VisibilityAnomalies,
			"/proc/sys/kernel/tainted 不可读: "+err.Error())
		return
	}
	taint := strings.TrimSpace(string(data))
	ir.KernelTaint = taint

	if taint != "0" {
		ir.VisibilityAnomalies = append(ir.VisibilityAnomalies,
			"内核 taint="+taint+" (非零)")
		// 解析 taint 位含义
		parseTaintBits(ir, taint)
	}
}

// parseTaintBits 解析 taint 位的含义
func parseTaintBits(ir *model.IntegrityResult, taintStr string) {
	var taint uint64
	for _, ch := range taintStr {
		if ch >= '0' && ch <= '9' {
			taint = taint*10 + uint64(ch-'0')
		}
	}

	taintFlags := map[uint64]string{
		1 << 0:  "P: 加载了专有模块",
		1 << 1:  "F: 强制加载了模块",
		1 << 2:  "S: 内核运行在不安全的 SMP 处理器上",
		1 << 3:  "R: 强制卸载了模块",
		1 << 4:  "M: 机器检查异常",
		1 << 5:  "B: 发生了坏页引用",
		1 << 6:  "U: 用户请求的 taint",
		1 << 7:  "D: 内核最近自行 OOPS",
		1 << 8:  "A: ACPI 表被覆盖",
		1 << 9:  "W: 内核发出了警告",
		1 << 10: "C: staging 驱动被加载",
		1 << 11: "I: 应用了内核补丁",
		1 << 12: "O: 加载了外部构建的(\"out-of-tree\")模块",
		1 << 13: "E: 加载了未签名模块",
	}

	for bit, desc := range taintFlags {
		if taint&bit != 0 {
			ir.VisibilityAnomalies = append(ir.VisibilityAnomalies,
				"taint 位: "+desc)
		}
	}
}

// checkModuleVisibility 对比 /proc/modules 和 /sys/module
func checkModuleVisibility(ir *model.IntegrityResult) {
	procModules, err := readProcModules()
	if err != nil {
		ir.VisibilityAnomalies = append(ir.VisibilityAnomalies,
			"/proc/modules 不可读: "+err.Error())
		return
	}

	sysModules, err := readSysModules()
	if err != nil {
		ir.VisibilityAnomalies = append(ir.VisibilityAnomalies,
			"/sys/module 不可读: "+err.Error())
		return
	}

	// /sys/module 中有但 /proc/modules 中没有的
	// 注意：/sys/module 还包含内置模块（built-in），这些不出现在 /proc/modules 中
	// 所以需要过滤掉有 /sys/module/<name>/initstate 且值为 "live" 的模块
	for name := range sysModules {
		if _, ok := procModules[name]; ok {
			continue
		}
		// 检查是否是 built-in 模块
		initState, err := os.ReadFile(fmt.Sprintf("/sys/module/%s/initstate", name))
		if err != nil {
			// 没有 initstate 文件的通常是 built-in 参数模块，忽略
			continue
		}
		state := strings.TrimSpace(string(initState))
		if state == "live" {
			// 状态为 live 但不在 /proc/modules 中——可疑
			ir.ModuleViewMismatch = append(ir.ModuleViewMismatch,
				fmt.Sprintf("模块 %s 在 /sys/module 中为 live 状态但不在 /proc/modules 中", name))
		}
	}

	// /proc/modules 中有但 /sys/module 中没有的（极少见但也异常）
	for name := range procModules {
		if _, ok := sysModules[name]; !ok {
			ir.ModuleViewMismatch = append(ir.ModuleViewMismatch,
				fmt.Sprintf("模块 %s 在 /proc/modules 中但不在 /sys/module 中", name))
		}
	}
}

// readProcModules 解析 /proc/modules，返回模块名集合
func readProcModules() (map[string]struct{}, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	modules := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			modules[fields[0]] = struct{}{}
		}
	}
	return modules, scanner.Err()
}

// readSysModules 列出 /sys/module 下的目录，返回模块名集合
func readSysModules() (map[string]struct{}, error) {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, err
	}

	modules := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			modules[entry.Name()] = struct{}{}
		}
	}
	return modules, nil
}
