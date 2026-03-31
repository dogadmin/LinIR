package elfutil

import (
	"debug/elf"
	"fmt"
	"strings"
)

// ELFInfo 包含取证相关的 ELF 元数据。
// 所有数据均通过 Go 标准库 debug/elf 直接解析，不调用 ldd、readelf 等外部命令。
//
// 为什么不用 ldd：
//   ldd 实际上会执行目标二进制的动态链接器（ld-linux.so），
//   如果目标是恶意文件，ldd 执行过程本身就可能被利用。
//   直接解析 ELF 格式不执行任何代码，安全得多。
type ELFInfo struct {
	IsELF        bool     `json:"is_elf"`
	Class        string   `json:"class,omitempty"`         // ELFCLASS32 | ELFCLASS64
	Machine      string   `json:"machine,omitempty"`       // EM_X86_64, EM_AARCH64 等
	Type         string   `json:"type,omitempty"`          // ET_EXEC, ET_DYN 等
	IsStripped   bool     `json:"is_stripped"`             // 无 .symtab
	IsPacked     bool     `json:"is_packed"`               // UPX 等壳
	IsStaticLink bool     `json:"is_static_linked"`        // 无 PT_INTERP
	Interpreter  string   `json:"interpreter,omitempty"`   // 动态链接器路径
	Imports      []string `json:"imports,omitempty"`       // DT_NEEDED 列表
	RPath        string   `json:"rpath,omitempty"`         // DT_RPATH
	RunPath      string   `json:"runpath,omitempty"`       // DT_RUNPATH
	HasPtrace    bool     `json:"has_ptrace,omitempty"`    // 导入了 ptrace 相关符号
	HasDlopen    bool     `json:"has_dlopen,omitempty"`    // 导入了 dlopen
}

// Analyze 解析指定路径的 ELF 文件，提取取证相关元数据。
func Analyze(path string) (*ELFInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return &ELFInfo{IsELF: false}, nil
	}
	defer f.Close()

	info := &ELFInfo{
		IsELF:   true,
		Class:   f.Class.String(),
		Machine: f.Machine.String(),
		Type:    f.Type.String(),
	}

	// 是否 stripped（无 .symtab section）
	if f.Section(".symtab") == nil {
		info.IsStripped = true
	}

	// PT_INTERP → 动态链接器路径，判断是否静态链接
	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			buf := make([]byte, p.Filesz)
			if _, err := p.ReadAt(buf, 0); err == nil {
				for len(buf) > 0 && buf[len(buf)-1] == 0 {
					buf = buf[:len(buf)-1]
				}
				info.Interpreter = string(buf)
			}
			break
		}
	}
	info.IsStaticLink = !hasInterp

	// DT_NEEDED → 动态库依赖
	imports, err := f.ImportedLibraries()
	if err == nil {
		info.Imports = imports
	}

	// 从 .dynamic section 解析 DT_RPATH / DT_RUNPATH
	info.RPath, info.RunPath = parseDynamicPaths(f)

	// UPX 检测：检查 section 名
	for _, s := range f.Sections {
		if s.Name == "UPX!" || s.Name == ".upx" || s.Name == "UPX0" || s.Name == "UPX1" {
			info.IsPacked = true
			break
		}
	}

	// 导入符号检查：ptrace / dlopen
	symbols, err := f.ImportedSymbols()
	if err == nil {
		for _, sym := range symbols {
			name := sym.Name
			if name == "ptrace" || name == "__ptrace" {
				info.HasPtrace = true
			}
			if name == "dlopen" || name == "__libc_dlopen_mode" {
				info.HasDlopen = true
			}
		}
	}

	return info, nil
}

// parseDynamicPaths 从 ELF 的 .dynamic section 中提取 DT_RPATH 和 DT_RUNPATH。
//
// 为什么关注这两个字段：
//   DT_RPATH / DT_RUNPATH 指定了动态库搜索路径。
//   如果这些路径指向 /tmp 或 other-writable 目录，攻击者可以
//   在那里放置恶意 .so 来劫持动态链接过程。
func parseDynamicPaths(f *elf.File) (rpath, runpath string) {
	// 使用 DynString 来获取 DT_RPATH 和 DT_RUNPATH
	rpaths, err := f.DynString(elf.DT_RPATH)
	if err == nil && len(rpaths) > 0 {
		rpath = strings.Join(rpaths, ":")
	}
	runpaths, err := f.DynString(elf.DT_RUNPATH)
	if err == nil && len(runpaths) > 0 {
		runpath = strings.Join(runpaths, ":")
	}
	return
}

// RiskAssessment 对 ELF 信息做风险评估，返回风险标记列表
func RiskAssessment(info *ELFInfo) []string {
	if !info.IsELF {
		return nil
	}
	var risks []string

	if info.IsPacked {
		risks = append(risks, "packed_binary")
	}
	if info.IsStripped && !info.IsStaticLink {
		// 动态链接且 stripped——常见于正常二进制，不单独标记
	}
	if info.HasPtrace {
		risks = append(risks, "imports_ptrace")
	}
	if info.HasDlopen {
		risks = append(risks, "imports_dlopen")
	}

	// RPATH / RUNPATH 指向可疑目录
	for _, pathList := range []string{info.RPath, info.RunPath} {
		for _, dir := range strings.Split(pathList, ":") {
			dir = strings.TrimSpace(dir)
			if dir == "" {
				continue
			}
			if strings.HasPrefix(dir, "/tmp") || strings.HasPrefix(dir, "/var/tmp") ||
				strings.HasPrefix(dir, "/dev/shm") || dir == "." || dir == "" ||
				strings.HasPrefix(dir, "$ORIGIN/../tmp") {
				risks = append(risks, "rpath_writable_dir:"+dir)
			}
		}
	}

	// 异常 interpreter（不是标准的 ld-linux）
	if info.Interpreter != "" &&
		!strings.Contains(info.Interpreter, "ld-linux") &&
		!strings.Contains(info.Interpreter, "ld-musl") &&
		!strings.Contains(info.Interpreter, "/lib64/ld-") &&
		!strings.Contains(info.Interpreter, "/lib/ld-") {
		risks = append(risks, "unusual_interpreter:"+info.Interpreter)
	}

	return risks
}

// FormatSummary 返回一行摘要用于日志
func FormatSummary(info *ELFInfo) string {
	if !info.IsELF {
		return "not ELF"
	}
	parts := []string{
		"ELF", info.Type, info.Machine,
	}
	if info.IsStaticLink {
		parts = append(parts, "static")
	}
	if info.IsStripped {
		parts = append(parts, "stripped")
	}
	if info.IsPacked {
		parts = append(parts, "PACKED")
	}
	return fmt.Sprintf("%s imports=%d interp=%s",
		strings.Join(parts, " "), len(info.Imports), info.Interpreter)
}
