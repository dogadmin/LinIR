package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EventWriter 输出命中事件
type EventWriter struct {
	outputDir  string
	jsonOutput bool
	textOutput bool
	bundleDir  string
	eventCount int
}

// NewEventWriter 创建事件输出器
func NewEventWriter(cfg WatchConfig) *EventWriter {
	return &EventWriter{
		outputDir:  cfg.OutputDir,
		jsonOutput: cfg.JSONOutput,
		textOutput: cfg.TextOutput,
	}
}

// WriteEvent 输出一个补采完成的事件
func (w *EventWriter) WriteEvent(evt EnrichedEvent) error {
	w.eventCount++

	// 1. 实时文本输出到 stdout
	if w.textOutput {
		w.writeText(evt)
	}

	// 2. JSON 追加到文件
	if w.jsonOutput && w.outputDir != "" {
		if err := w.writeJSON(evt); err != nil {
			return err
		}
	}

	// 3. Bundle 输出
	if w.bundleDir != "" {
		if err := w.writeBundle(evt); err != nil {
			return err
		}
	}

	return nil
}

func (w *EventWriter) writeText(evt EnrichedEvent) {
	// 颜色前缀
	sevColor := ""
	resetColor := "\033[0m"
	switch evt.Severity {
	case "critical":
		sevColor = "\033[1;31m" // 红色粗体
	case "high":
		sevColor = "\033[31m" // 红色
	case "medium":
		sevColor = "\033[33m" // 黄色
	case "low":
		sevColor = "\033[36m" // 青色
	default:
		sevColor = "\033[0m"
		resetColor = ""
	}

	proc := "unknown"
	exe := ""
	if evt.Process != nil {
		proc = evt.Process.Name
		exe = evt.Process.Exe
	}

	fmt.Printf("%s[%s]%s %s IOC=%s PID=%d Process=%s Exe=%s Remote=%s:%d Score=%d Confidence=%s\n",
		sevColor, strings.ToUpper(evt.Severity), resetColor,
		evt.Timestamp.Format("15:04:05"),
		evt.IOC.Value, evt.Connection.PID, proc, exe,
		evt.Connection.RemoteAddress, evt.Connection.RemotePort,
		evt.Score, evt.Confidence)

	// 输出证据摘要
	for _, e := range evt.Evidence {
		fmt.Printf("  +%d [%s] %s\n", e.Score, e.Domain, e.Description)
	}
	fmt.Println()
}

func (w *EventWriter) writeJSON(evt EnrichedEvent) error {
	filename := fmt.Sprintf("linir-watch-%s.jsonl", time.Now().Format("20060102"))
	path := filepath.Join(w.outputDir, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	f.Write(data)
	f.Write([]byte("\n"))
	return nil
}

func (w *EventWriter) writeBundle(evt EnrichedEvent) error {
	eventDir := filepath.Join(w.bundleDir, fmt.Sprintf("event_%03d_%s", w.eventCount, evt.EventID))
	if err := os.MkdirAll(eventDir, 0755); err != nil {
		return err
	}

	// 写完整事件 JSON
	writeJSONFile(filepath.Join(eventDir, "event.json"), evt)

	// 写摘要文本
	writeTextFile(filepath.Join(eventDir, "summary.txt"), evt.Summary)

	// 写进程信息
	if evt.Process != nil {
		writeJSONFile(filepath.Join(eventDir, "process.json"), evt.Process)
	}

	// 写持久化信息
	if len(evt.Persistence) > 0 {
		writeJSONFile(filepath.Join(eventDir, "persistence.json"), evt.Persistence)
	}

	return nil
}

func writeJSONFile(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(path, data, 0644)
}

func writeTextFile(path, content string) {
	os.WriteFile(path, []byte(content+"\n"), 0644)
}

// EventCount 返回已输出的事件数
func (w *EventWriter) EventCount() int {
	return w.eventCount
}
