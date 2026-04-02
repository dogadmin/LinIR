package score

// 规则 ID 常量——collect 和 watch 共用，避免字符串散落
const (
	// 进程域
	RuleExeInTmp             = "exe_in_tmp"
	RuleExeInTmpNetworked    = "exe_in_tmp_networked"
	RuleExeInTmpInterpreter  = "exe_in_tmp_interpreter"
	RuleExeDeleted           = "exe_deleted"
	RuleExeDeletedNetworked  = "exe_deleted_networked"
	RuleWebshellStrong       = "webshell_indicator_strong"
	RuleWebshellWeak         = "webshell_indicator_weak"
	RuleFakeKthread          = "fake_kthread"
	RuleFakeKthreadNetworked = "fake_kthread_networked"
	RulePersistNetworked     = "persistent_networked"
	RulePersistNetworkedPath = "persistent_networked_abnormal_path"
	RuleProcessInvisible     = "process_invisible"

	// 网络域
	RuleSuspiciousPort = "suspicious_port"

	// 持久化域
	RulePersistInTmp       = "persist_in_tmp"
	RulePersistInTmpActive = "persist_in_tmp_active"
	RulePersistInTmpActNet = "persist_in_tmp_active_net"
	RulePreloadPresent     = "global_ld_preload_present"
	RulePreloadPathAbnorm  = "preload_path_abnormal"
	RuleReverseShell       = "reverse_shell_strong"
	RuleReverseShellActive = "reverse_shell_active"
	RulePipeShell          = "pipe_shell"
	RulePipeShellActive    = "pipe_shell_active"
	RuleProfileLdPreload   = "profile_ld_preload"
	RuleProfileDyldInsert  = "profile_dyld_insert"
	RuleSystemdEnvPreload  = "systemd_env_ld_preload"
	RulePersistActiveNet   = "persist_active_net"
	RulePersistActNetAbnorm = "persist_active_net_abnormal"

	// 完整性域
	RuleRootkitSuspected  = "rootkit_suspected"
	RuleModuleMismatch    = "module_mismatch"
	RuleHostTrustLowLoader = "host_trust_low_loader"

	// YARA 域
	RuleYaraHitCritical      = "yara_hit_critical"
	RuleYaraHitHigh          = "yara_hit_high"
	RuleYaraHitMedium        = "yara_hit_medium"
	RuleYaraHitLow           = "yara_hit_low"
	RuleYaraOnActiveProcess  = "yara_on_active_process"
	RuleYaraAbnormalPath     = "yara_abnormal_path_bonus"
	RuleYaraOnPersistTarget  = "yara_on_persistence_target"

	// IOC 域（watch only）
	RuleIOCHit = "ioc_hit"

	// 组合域
	RuleComboTmpYara          = "combo_tmp_exec_and_yara"
	RuleComboTmpPersist       = "combo_tmp_exec_and_persist"
	RuleComboDeletedPersist   = "combo_deleted_and_persist"
	RuleComboWebshellNetwork  = "combo_webshell_and_network"
	RuleComboPreloadActive    = "combo_preload_and_active_process"
	RuleComboPersistYaraNet   = "combo_persistence_yara_network"
	RuleComboRootkitSusp      = "combo_rootkit_plus_active_suspicious"
	RuleComboIOCTmpExec       = "combo_ioc_tmp_exec"
	RuleComboIOCDeleted       = "combo_ioc_deleted_exec"
	RuleComboIOCPersistence   = "combo_ioc_persistence"
	RuleComboIOCYara          = "combo_ioc_yara"
	RuleComboIOCWebshell      = "combo_ioc_webshell"
	RuleComboIOCPersistYara   = "combo_ioc_persist_yara"

	// 二进制域（watch only）
	RuleBinaryInTmp   = "binary_in_tmp"
	RuleBinaryMissing = "binary_missing"

	// 持久化域（watch only）
	RulePersistenceLinked   = "persistence_linked"
	RulePersistLinkedAbnorm = "persistence_linked_abnormal"
	RuleYaraOnTmpBinary     = "yara_on_tmp_binary"

	// Retained 域
	RuleRetainedPersistChanged     = "retained_persist_changed"
	RuleRetainedPersistTmpTarget   = "retained_persist_tmp_target"
	RuleRetainedDeletedExe         = "retained_deleted_exe"
	RuleRetainedTmpExecutable      = "retained_tmp_executable"
	RuleRetainedFailedLogins       = "retained_failed_logins"

	// Triggerable 域
	RuleTriggerableTmpAutostart    = "triggerable_tmp_autostart"
	RuleTriggerableReverseShellCron = "triggerable_reverse_shell_cron"
	RuleTriggerablePipeShellCron   = "triggerable_pipe_shell_cron"

	// 跨状态组合域
	RuleCrossRetainedTriggerable      = "cross_retained_and_triggerable"
	RuleCrossRetainedRuntime          = "cross_retained_and_runtime"
	RuleCrossPersistRunningKeepalive  = "cross_persist_running_keepalive"
)

// YaraScoreByHint 返回 YARA 命中的分值和严重度（collect 和 watch 共用）
func YaraScoreByHint(hint string) (score int, severity string) {
	switch hint {
	case "critical":
		return 25, "critical"
	case "high":
		return 20, "high"
	case "medium":
		return 15, "medium"
	default:
		return 10, "low"
	}
}

// SeverityFromScore 根据总分返回严重度等级（collect 和 watch 共用）
func SeverityFromScore(total int) string {
	return severityFromScore(total)
}

// IsInterpreterProcess 判断进程名是否为 shell/interpreter（collect 和 watch 共用）
func IsInterpreterProcess(name string) bool {
	return isInterpreterName(name)
}

// IsInTmpDir 判断路径是否在临时目录（collect 和 watch 共用）
func IsInTmpDir(path string) bool {
	return isInTmp(path)
}
