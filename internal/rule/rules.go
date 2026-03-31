package rule

// Rule 定义单条评分规则
type Rule struct {
	Name        string
	Domain      string
	Description string
	Score       int
	Severity    string
}

// DefaultRules 返回内置评分规则。
// 设计原则：只为明确的入侵指标评分，不为正常系统行为评分。
// 每条规则应该是：如果在干净系统上触发，安全人员会认为这是误报。
func DefaultRules() []Rule {
	return []Rule{
		// 进程——明确异常
		{Name: "exe_in_tmp", Domain: "process", Description: "进程可执行文件位于临时目录", Score: 25, Severity: "high"},
		{Name: "exe_deleted", Domain: "process", Description: "进程可执行文件已从磁盘删除", Score: 10, Severity: "medium"},
		{Name: "webshell_indicator", Domain: "process", Description: "Web 服务器直接派生 shell 进程", Score: 25, Severity: "high"},
		{Name: "fake_kthread", Domain: "process", Description: "进程伪装内核线程(PPID≠2)", Score: 20, Severity: "high"},
		{Name: "persistent_networked", Domain: "process", Description: "持久化目标正在运行且有网络连接", Score: 15, Severity: "medium"},

		// 网络——明确异常
		{Name: "suspicious_port", Domain: "network", Description: "连接到已知 C2 端口", Score: 20, Severity: "high"},
		{Name: "orphan_connections", Domain: "network", Description: "活跃连接无归属进程", Score: 10, Severity: "medium"},

		// 持久化——明确异常
		{Name: "persist_in_tmp", Domain: "persistence", Description: "持久化目标位于临时目录", Score: 25, Severity: "high"},
		{Name: "ld_preload", Domain: "persistence", Description: "系统级 ld.so.preload 注入", Score: 30, Severity: "high"},
		{Name: "reverse_shell", Domain: "persistence", Description: "/dev/tcp 反弹 shell 模式", Score: 30, Severity: "critical"},
		{Name: "pipe_shell", Domain: "persistence", Description: "curl/wget 管道到 shell 执行", Score: 15, Severity: "medium"},
		{Name: "persist_active_net", Domain: "persistence", Description: "持久化目标正在运行且有网络连接", Score: 15, Severity: "medium"},

		// 完整性——明确异常
		{Name: "rootkit_suspected", Domain: "integrity", Description: "多项可见性异常指向 rootkit", Score: 30, Severity: "critical"},
		{Name: "module_mismatch", Domain: "integrity", Description: "内核模块视图不一致", Score: 25, Severity: "high"},
		{Name: "host_trust_low", Domain: "integrity", Description: "主机环境可信度低", Score: 20, Severity: "medium"},

		// YARA
		{Name: "yara_hit", Domain: "yara", Description: "YARA 规则命中", Score: 30, Severity: "high"},
	}
}
