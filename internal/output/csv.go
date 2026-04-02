package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// CSVWriter 将采集结果导出为多个 CSV 文件。
// 每个数据域（进程、连接、持久化等）各一个 CSV，方便在 Excel/WPS/LibreOffice 中打开。
type CSVWriter struct {
	outputDir string
}

func NewCSVWriter(outputDir string) *CSVWriter {
	return &CSVWriter{outputDir: outputDir}
}

func (w *CSVWriter) Write(result *model.CollectionResult) error {
	id := result.CollectionID
	if len(id) > 8 {
		id = id[:8]
	}
	hostname := result.Host.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	prefix := fmt.Sprintf("linir-%s-%s", hostname, id)

	// 概览表
	if err := w.writeSummary(prefix, result); err != nil {
		return err
	}
	// 进程表
	if len(result.Processes) > 0 {
		if err := w.writeProcesses(prefix, result.Processes); err != nil {
			return err
		}
	}
	// 连接表
	if len(result.Connections) > 0 {
		if err := w.writeConnections(prefix, result.Connections); err != nil {
			return err
		}
	}
	// 持久化表
	if len(result.Persistence) > 0 {
		if err := w.writePersistence(prefix, result.Persistence); err != nil {
			return err
		}
	}
	// 评分证据表
	if result.Score != nil && len(result.Score.Evidence) > 0 {
		if err := w.writeEvidence(prefix, result.Score); err != nil {
			return err
		}
	}
	// YARA 命中表
	if len(result.YaraHits) > 0 {
		if err := w.writeYaraHits(prefix, result.YaraHits); err != nil {
			return err
		}
	}
	// 完整性表
	if result.Integrity != nil {
		if err := w.writeIntegrity(prefix, result.Integrity); err != nil {
			return err
		}
	}

	return nil
}

func (w *CSVWriter) createCSV(name string) (*os.File, *csv.Writer, error) {
	path := filepath.Join(w.outputDir, name)
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	// 写 UTF-8 BOM，让 Excel 正确识别中文
	f.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(f)
	return f, cw, nil
}

// ========== 概览 ==========

func (w *CSVWriter) writeSummary(prefix string, r *model.CollectionResult) error {
	f, cw, err := w.createCSV(prefix + "-summary.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"项目", "值"})
	cw.Write([]string{"主机名", r.Host.Hostname})
	cw.Write([]string{"平台", r.Host.Platform})
	cw.Write([]string{"内核版本", r.Host.KernelVersion})
	cw.Write([]string{"采集ID", r.CollectionID})
	cw.Write([]string{"采集时间", r.StartedAt.Format("2006-01-02 15:04:05")})
	cw.Write([]string{"耗时(ms)", fmt.Sprintf("%d", r.DurationMS)})
	cw.Write([]string{"采集可信度", r.SelfCheck.CollectionConfidence})
	cw.Write([]string{"主机可信度", r.Preflight.HostTrustLevel})

	if r.Score != nil {
		cw.Write([]string{"风险总分", fmt.Sprintf("%d", r.Score.Total)})
		cw.Write([]string{"风险等级", r.Score.Severity})
		cw.Write([]string{"证据数量", fmt.Sprintf("%d", len(r.Score.Evidence))})
	}

	cw.Write([]string{"进程数量", fmt.Sprintf("%d", len(r.Processes))})
	cw.Write([]string{"连接数量", fmt.Sprintf("%d", len(r.Connections))})
	cw.Write([]string{"持久化项数量", fmt.Sprintf("%d", len(r.Persistence))})
	cw.Write([]string{"YARA命中数量", fmt.Sprintf("%d", len(r.YaraHits))})
	cw.Write([]string{"采集错误数量", fmt.Sprintf("%d", len(r.Errors))})

	// LD_PRELOAD / DYLD 检测
	if r.SelfCheck.LDPreloadPresent {
		cw.Write([]string{"LD_PRELOAD", "检测到"})
	}
	if r.SelfCheck.DYLDInjectionPresent {
		cw.Write([]string{"DYLD注入", "检测到"})
	}

	// 预检异常
	for _, a := range r.Preflight.LoaderAnomaly {
		cw.Write([]string{"Loader异常", a})
	}
	for _, a := range r.Preflight.PathAnomaly {
		cw.Write([]string{"PATH异常", a})
	}

	// 错误
	for _, e := range r.Errors {
		cw.Write([]string{"采集错误[" + e.Phase + "]", e.Message})
	}

	return nil
}

// ========== 进程表 ==========

func (w *CSVWriter) writeProcesses(prefix string, procs []model.ProcessInfo) error {
	f, cw, err := w.createCSV(prefix + "-processes.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{
		"PID", "PPID", "用户", "进程名", "可执行路径", "命令行",
		"工作目录", "UID", "GID", "启动时间",
		"FD数", "Socket数", "可疑标记", "可信度",
	})

	for _, p := range procs {
		cmdline := strings.Join(p.Cmdline, " ")
		if len(cmdline) > 500 {
			cmdline = cmdline[:500] + "..."
		}
		flags := strings.Join(p.SuspiciousFlags, ", ")

		cw.Write([]string{
			itoa(p.PID), itoa(p.PPID), p.Username, p.Name, p.Exe, cmdline,
			p.Cwd, itoa(p.UID), itoa(p.GID), p.StartTime,
			itoa(p.FDCount), itoa(len(p.SocketInodes)), flags, p.Confidence,
		})
	}
	return nil
}

// ========== 连接表 ==========

func (w *CSVWriter) writeConnections(prefix string, conns []model.ConnectionInfo) error {
	f, cw, err := w.createCSV(prefix + "-connections.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{
		"协议", "地址族", "本地地址", "本地端口", "远端地址", "远端端口",
		"状态", "PID", "进程名", "可疑标记", "可信度",
	})

	for _, c := range conns {
		flags := strings.Join(c.SuspiciousFlags, ", ")
		cw.Write([]string{
			c.Proto, c.Family, c.LocalAddress, uitoa16(c.LocalPort),
			c.RemoteAddress, uitoa16(c.RemotePort),
			c.State, itoa(c.PID), c.ProcessName, flags, c.Confidence,
		})
	}
	return nil
}

// ========== 持久化表 ==========

func (w *CSVWriter) writePersistence(prefix string, items []model.PersistenceItem) error {
	f, cw, err := w.createCSV(prefix + "-persistence.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{
		"类型", "路径", "目标", "作用域", "风险标记", "目标存在", "可信度", "关键字段",
	})

	for _, item := range items {
		flags := strings.Join(item.RiskFlags, ", ")
		exists := "是"
		if !item.Exists {
			exists = "否"
		}
		// 将 ParsedFields 压缩为一行
		var fields []string
		for k, v := range item.ParsedFields {
			if v != "" {
				fields = append(fields, k+"="+v)
			}
		}
		cw.Write([]string{
			item.Type, item.Path, item.Target, item.UserScope,
			flags, exists, item.Confidence, strings.Join(fields, "; "),
		})
	}
	return nil
}

// ========== 评分证据表 ==========

func (w *CSVWriter) writeEvidence(prefix string, score *model.ScoreResult) error {
	f, cw, err := w.createCSV(prefix + "-evidence.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	// 总分行
	cw.Write([]string{"总分", "严重度", "可信度", "摘要"})
	cw.Write([]string{
		itoa(score.Total), score.Severity, score.Confidence, score.Summary,
	})
	cw.Write([]string{}) // 空行分隔

	// 证据明细
	cw.Write([]string{"域", "规则", "描述", "分值", "严重度"})
	for _, e := range score.Evidence {
		cw.Write([]string{
			e.Domain, e.Rule, e.Description, itoa(e.Score), e.Severity,
		})
	}
	return nil
}

// ========== YARA 命中表 ==========

func (w *CSVWriter) writeYaraHits(prefix string, hits []model.YaraHit) error {
	f, cw, err := w.createCSV(prefix + "-yara.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{
		"规则名", "目标类型", "目标路径", "命中字符串", "严重度提示", "关联PID",
	})

	for _, h := range hits {
		cw.Write([]string{
			h.Rule, h.TargetType, h.TargetPath,
			strings.Join(h.Strings, ", "), h.SeverityHint, itoa(h.LinkedPID),
		})
	}
	return nil
}

// ========== 完整性表 ==========

func (w *CSVWriter) writeIntegrity(prefix string, ir *model.IntegrityResult) error {
	f, cw, err := w.createCSV(prefix + "-integrity.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"检查类别", "发现"})

	suspected := "否"
	if ir.RootkitSuspected {
		suspected = "是"
	}
	cw.Write([]string{"Rootkit疑似", suspected})
	cw.Write([]string{"内核Taint", ir.KernelTaint})

	for _, item := range ir.ProcessViewMismatch {
		cw.Write([]string{"进程视图不一致", item})
	}
	for _, item := range ir.NetworkViewMismatch {
		cw.Write([]string{"网络视图不一致", item})
	}
	for _, item := range ir.FileViewMismatch {
		cw.Write([]string{"文件视图不一致", item})
	}
	for _, item := range ir.ModuleViewMismatch {
		cw.Write([]string{"模块视图不一致", item})
	}
	for _, item := range ir.VisibilityAnomalies {
		cw.Write([]string{"可见性异常", item})
	}
	for _, item := range ir.RecommendedAction {
		cw.Write([]string{"建议操作", item})
	}

	return nil
}

// ========== 三维状态分析 ==========

func (w *CSVWriter) WriteAnalysis(result *model.AnalysisResult) error {
	id := result.AnalysisID
	if len(id) > 8 {
		id = id[:8]
	}
	hostname := result.Host.Hostname
	if hostname == "" {
		hostname = "unknown"
	}
	prefix := fmt.Sprintf("linir-analysis-%s-%s", hostname, id)

	// Runtime CSV tables (write with analysis prefix for consistent naming)
	if result.Runtime != nil {
		if err := w.writeRuntimeTables(prefix, result.Runtime); err != nil {
			return err
		}
	}

	// Retained: file timeline
	if result.Retained != nil && len(result.Retained.FileTimeline) > 0 {
		if err := w.writeRetainedFiles(prefix, result.Retained.FileTimeline); err != nil {
			return err
		}
	}

	// Retained: persistence changes
	if result.Retained != nil && len(result.Retained.PersistChanges) > 0 {
		if err := w.writeRetainedPersistence(prefix, result.Retained.PersistChanges); err != nil {
			return err
		}
	}

	// Retained: artifacts
	if result.Retained != nil && len(result.Retained.Artifacts) > 0 {
		if err := w.writeRetainedArtifacts(prefix, result.Retained.Artifacts); err != nil {
			return err
		}
	}

	// Retained: auth history
	if result.Retained != nil && len(result.Retained.AuthHistory) > 0 {
		if err := w.writeRetainedAuth(prefix, result.Retained.AuthHistory); err != nil {
			return err
		}
	}

	// Retained: log events
	if result.Retained != nil && len(result.Retained.LogEvents) > 0 {
		if err := w.writeRetainedLogs(prefix, result.Retained.LogEvents); err != nil {
			return err
		}
	}

	// Triggerable
	if result.Triggerable != nil {
		t := result.Triggerable
		all := make([]model.TriggerableEntry, 0, len(t.Autostarts)+len(t.Scheduled)+len(t.Keepalive))
		all = append(all, t.Autostarts...)
		all = append(all, t.Scheduled...)
		all = append(all, t.Keepalive...)
		if len(all) > 0 {
			if err := w.writeTriggerable(prefix, all); err != nil {
				return err
			}
		}
	}

	// Timeline
	if len(result.Timeline) > 0 {
		if err := w.writeTimeline(prefix, result.Timeline); err != nil {
			return err
		}
	}

	return nil
}

func (w *CSVWriter) writeRuntimeTables(prefix string, r *model.CollectionResult) error {
	if err := w.writeSummary(prefix, r); err != nil {
		return err
	}
	if len(r.Processes) > 0 {
		if err := w.writeProcesses(prefix, r.Processes); err != nil {
			return err
		}
	}
	if len(r.Connections) > 0 {
		if err := w.writeConnections(prefix, r.Connections); err != nil {
			return err
		}
	}
	if len(r.Persistence) > 0 {
		if err := w.writePersistence(prefix, r.Persistence); err != nil {
			return err
		}
	}
	if r.Score != nil && len(r.Score.Evidence) > 0 {
		if err := w.writeEvidence(prefix, r.Score); err != nil {
			return err
		}
	}
	if len(r.YaraHits) > 0 {
		if err := w.writeYaraHits(prefix, r.YaraHits); err != nil {
			return err
		}
	}
	if r.Integrity != nil {
		if err := w.writeIntegrity(prefix, r.Integrity); err != nil {
			return err
		}
	}
	return nil
}

func (w *CSVWriter) writeRetainedFiles(prefix string, entries []model.RetainedFileEntry) error {
	f, cw, err := w.createCSV(prefix + "-retained-files.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"路径", "大小", "权限", "UID", "GID", "修改时间", "变更时间", "可执行", "关键目录", "风险标记", "可信度"})
	for _, e := range entries {
		exec := "否"
		if e.Executable {
			exec = "是"
		}
		cw.Write([]string{
			e.Path, fmt.Sprintf("%d", e.Size), e.Mode,
			itoa(e.UID), itoa(e.GID),
			e.ModTime.Format("2006-01-02 15:04:05"),
			e.ChangeTime.Format("2006-01-02 15:04:05"),
			exec, e.KeyDir, strings.Join(e.RiskFlags, ", "), e.Confidence,
		})
	}
	return nil
}

func (w *CSVWriter) writeRetainedPersistence(prefix string, changes []model.PersistenceChange) error {
	f, cw, err := w.createCSV(prefix + "-retained-persistence.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"类型", "路径", "目标", "修改时间", "变更类型", "风险标记", "可信度"})
	for _, c := range changes {
		cw.Write([]string{
			c.Type, c.Path, c.Target,
			c.ModTime.Format("2006-01-02 15:04:05"),
			c.ChangeType, strings.Join(c.RiskFlags, ", "), c.Confidence,
		})
	}
	return nil
}

func (w *CSVWriter) writeRetainedArtifacts(prefix string, artifacts []model.ArtifactFinding) error {
	f, cw, err := w.createCSV(prefix + "-retained-artifacts.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"类型", "路径", "关联PID", "关联项", "原因", "来源", "可信度"})
	for _, a := range artifacts {
		cw.Write([]string{
			a.Type, a.Path, itoa(a.LinkedPID), a.LinkedItem,
			a.Reason, a.Source, a.Confidence,
		})
	}
	return nil
}

func (w *CSVWriter) writeRetainedAuth(prefix string, events []model.AuthEvent) error {
	f, cw, err := w.createCSV(prefix + "-retained-auth.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"时间", "类型", "用户", "来源IP", "终端", "成功", "数据源", "详情"})
	for _, e := range events {
		success := "是"
		if !e.Success {
			success = "否"
		}
		details := ""
		for k, v := range e.Details {
			if details != "" {
				details += "; "
			}
			details += k + "=" + v
		}
		cw.Write([]string{
			e.Time.Format("2006-01-02 15:04:05"),
			e.Type, e.User, e.RemoteIP, e.Terminal,
			success, e.Source, details,
		})
	}
	return nil
}

func (w *CSVWriter) writeRetainedLogs(prefix string, events []model.LogEvent) error {
	f, cw, err := w.createCSV(prefix + "-retained-logs.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"时间", "进程", "严重度", "数据源", "消息"})
	for _, e := range events {
		msg := e.Message
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		cw.Write([]string{
			e.Time.Format("2006-01-02 15:04:05"),
			e.Process, e.Severity, e.Source, msg,
		})
	}
	return nil
}

func (w *CSVWriter) writeTriggerable(prefix string, entries []model.TriggerableEntry) error {
	f, cw, err := w.createCSV(prefix + "-triggerable.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"类型", "分类", "路径", "目标", "触发条件", "调度", "下次触发", "作用域", "已启用", "风险标记", "可信度"})
	for _, e := range entries {
		enabled := "否"
		if e.Enabled {
			enabled = "是"
		}
		cw.Write([]string{
			e.Type, e.Category, e.Path, e.Target,
			e.TriggerCondition, e.Schedule, e.NextFire,
			e.UserScope, enabled, strings.Join(e.RiskFlags, ", "), e.Confidence,
		})
	}
	return nil
}

func (w *CSVWriter) writeTimeline(prefix string, events []model.TimelineEvent) error {
	f, cw, err := w.createCSV(prefix + "-timeline.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	defer cw.Flush()

	cw.Write([]string{"时间", "时间类型", "范围", "事件类型", "对象", "严重度", "可信度", "来源", "摘要"})
	for _, e := range events {
		timeStr := e.Time.Format("2006-01-02 15:04:05")
		if e.TimeType == "synthetic" {
			timeStr = e.SynthLabel
		}
		cw.Write([]string{
			timeStr, e.TimeType, e.Scope, e.Type, e.Object,
			e.Severity, e.Confidence, e.Source, e.Summary,
		})
	}
	return nil
}

// ========== 辅助 ==========

func itoa(v int) string {
	return fmt.Sprintf("%d", v)
}

func uitoa16(v uint16) string {
	return fmt.Sprintf("%d", v)
}
