package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

const (
	// 国内 Token Plan: Anthropic 兼容端点
	minimaxEndpoint = "https://api.minimaxi.com/anthropic/v1/messages"
	maxContextChars = 8000
	maxOutputTokens = 4096
)

var httpClient = &http.Client{Timeout: 120 * time.Second}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`    // "user" or "assistant"
	Content string `json:"content"`
}

// anthropicRequest is the Anthropic Messages API request format.
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
}

// anthropicResponse is the Anthropic Messages API response format.
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ChatCompletion calls MiniMax Token Plan API (Anthropic-compatible) and returns the reply.
func ChatCompletion(ctx context.Context, apiKey, modelName string, systemPrompt string, messages []Message) (string, error) {
	// Anthropic format: system is a top-level field, not in messages array
	// Messages must alternate user/assistant, starting with user
	cleanMsgs := sanitizeMessages(messages)

	reqBody := anthropicRequest{
		Model:     modelName,
		MaxTokens: maxOutputTokens,
		System:    systemPrompt,
		Messages:  cleanMsgs,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", minimaxEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API 返回 %d: %s", resp.StatusCode, truncate(string(respBytes), 500))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBytes, &anthropicResp); err != nil {
		return "", fmt.Errorf("解析响应: %w\n原始: %s", err, truncate(string(respBytes), 500))
	}

	if anthropicResp.Error != nil {
		return "", fmt.Errorf("API 错误: [%s] %s", anthropicResp.Error.Type, anthropicResp.Error.Message)
	}

	// Extract text from content blocks
	var textParts []string
	for _, block := range anthropicResp.Content {
		if block.Type == "text" && block.Text != "" {
			textParts = append(textParts, block.Text)
		}
	}
	if len(textParts) == 0 {
		return "", fmt.Errorf("API 返回空内容。原始: %s", truncate(string(respBytes), 500))
	}

	return strings.Join(textParts, "\n"), nil
}

// sanitizeMessages ensures messages alternate user/assistant starting with user.
// Anthropic API requires this strict alternation.
func sanitizeMessages(msgs []Message) []Message {
	if len(msgs) == 0 {
		return []Message{{Role: "user", Content: "请分析"}}
	}

	var clean []Message
	for _, m := range msgs {
		role := m.Role
		// Map "system" role to skip (system is a top-level field in Anthropic)
		if role == "system" {
			continue
		}
		// Ensure valid role
		if role != "user" && role != "assistant" {
			role = "user"
		}
		// Prevent consecutive same-role messages
		if len(clean) > 0 && clean[len(clean)-1].Role == role {
			clean[len(clean)-1].Content += "\n" + m.Content
			continue
		}
		clean = append(clean, Message{Role: role, Content: m.Content})
	}

	// Must start with user
	if len(clean) == 0 || clean[0].Role != "user" {
		clean = append([]Message{{Role: "user", Content: "请分析"}}, clean...)
	}

	return clean
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// StripThinking removes <think>...</think> blocks from AI output.
func StripThinking(text string) string {
	for {
		start := strings.Index(text, "<think>")
		if start < 0 {
			break
		}
		end := strings.Index(text, "</think>")
		if end < 0 {
			text = text[:start]
			break
		}
		text = text[:start] + text[end+len("</think>"):]
	}
	text = strings.ReplaceAll(text, "</think>", "")
	return strings.TrimSpace(text)
}

// BuildForensicContext creates a concise system prompt from forensic results.
func BuildForensicContext(result *model.CollectionResult, analysis *model.AnalysisResult) string {
	var b strings.Builder
	b.WriteString(`你是一名资深安全应急响应专家。以下是自动采集的主机取证数据。
规则：
- 直接输出结论和建议，不要输出思考过程
- 语言简洁干练，用安全从业者的专业术语
- 用中文回答
- 如果没有发现明显威胁，直接说明

`)

	if result == nil && analysis == nil {
		b.WriteString("注意：当前没有采集数据。请提醒用户先执行采集。\n")
		return b.String()
	}

	// Host info
	if analysis != nil {
		h := analysis.Host
		b.WriteString(fmt.Sprintf("## 主机信息\n主机名: %s\n平台: %s\n内核: %s\n", h.Hostname, h.Platform, h.KernelVersion))
	} else if result != nil {
		h := result.Host
		b.WriteString(fmt.Sprintf("## 主机信息\n主机名: %s\n平台: %s\n内核: %s\n", h.Hostname, h.Platform, h.KernelVersion))
	}

	// Score
	var score *model.ScoreResult
	if result != nil {
		score = result.Score
	} else if analysis != nil && analysis.Runtime != nil {
		score = analysis.Runtime.Score
	}
	if score != nil {
		b.WriteString(fmt.Sprintf("\n## 风险评分\n总分: %d/100 (%s)\n可信度: %s\n", score.Total, score.Severity, score.Confidence))
		if len(score.Evidence) > 0 {
			b.WriteString("证据:\n")
			for i, e := range score.Evidence {
				if i >= 20 {
					b.WriteString(fmt.Sprintf("... 另有 %d 条证据\n", len(score.Evidence)-20))
					break
				}
				b.WriteString(fmt.Sprintf("- [%s] %s/%s: %s (+%d)\n", e.Severity, e.Domain, e.Rule, e.Description, e.Score))
			}
		}
	}

	// Suspicious processes
	if result != nil && len(result.Processes) > 0 {
		var suspicious []model.ProcessInfo
		for _, p := range result.Processes {
			if len(p.SuspiciousFlags) > 0 {
				suspicious = append(suspicious, p)
			}
		}
		if len(suspicious) > 0 {
			b.WriteString(fmt.Sprintf("\n## 可疑进程 (%d)\n", len(suspicious)))
			for i, p := range suspicious {
				if i >= 15 {
					b.WriteString(fmt.Sprintf("... 另有 %d 个可疑进程\n", len(suspicious)-15))
					break
				}
				b.WriteString(fmt.Sprintf("- PID %d (%s) exe=%s flags=[%s]\n", p.PID, p.Name, p.Exe, strings.Join(p.SuspiciousFlags, ",")))
			}
		}
	}

	// Suspicious connections
	if result != nil && len(result.Connections) > 0 {
		var suspicious []model.ConnectionInfo
		for _, c := range result.Connections {
			if len(c.SuspiciousFlags) > 0 {
				suspicious = append(suspicious, c)
			}
		}
		if len(suspicious) > 0 {
			b.WriteString(fmt.Sprintf("\n## 可疑网络连接 (%d)\n", len(suspicious)))
			for i, c := range suspicious {
				if i >= 10 {
					break
				}
				b.WriteString(fmt.Sprintf("- %s %s:%d→%s:%d PID=%d flags=[%s]\n", c.Proto, c.LocalAddress, c.LocalPort, c.RemoteAddress, c.RemotePort, c.PID, strings.Join(c.SuspiciousFlags, ",")))
			}
		}
	}

	// Persistence with risk flags
	if result != nil && len(result.Persistence) > 0 {
		var risky []model.PersistenceItem
		for _, p := range result.Persistence {
			if len(p.RiskFlags) > 0 {
				risky = append(risky, p)
			}
		}
		if len(risky) > 0 {
			b.WriteString(fmt.Sprintf("\n## 有风险持久化项 (%d)\n", len(risky)))
			for i, p := range risky {
				if i >= 10 {
					break
				}
				b.WriteString(fmt.Sprintf("- [%s] %s → %s flags=[%s]\n", p.Type, p.Path, p.Target, strings.Join(p.RiskFlags, ",")))
			}
		}
	}

	// Integrity
	if result != nil && result.Integrity != nil && result.Integrity.RootkitSuspected {
		b.WriteString("\n## 完整性异常\nRootkit 疑似: 是\n")
		for _, a := range result.Integrity.VisibilityAnomalies {
			b.WriteString(fmt.Sprintf("- %s\n", a))
		}
	}

	// YARA hits
	if result != nil && len(result.YaraHits) > 0 {
		b.WriteString(fmt.Sprintf("\n## YARA 命中 (%d)\n", len(result.YaraHits)))
		for i, y := range result.YaraHits {
			if i >= 10 {
				break
			}
			b.WriteString(fmt.Sprintf("- 规则 %s 命中 %s (%s)\n", y.Rule, y.TargetPath, y.SeverityHint))
		}
	}

	// Retained summary
	if analysis != nil && analysis.Retained != nil {
		r := analysis.Retained
		b.WriteString(fmt.Sprintf("\n## 历史残留态（窗口: %s）\n", r.Window))
		b.WriteString(fmt.Sprintf("文件变更: %d 项\n", len(r.FileTimeline)))
		b.WriteString(fmt.Sprintf("持久化变更: %d 项\n", len(r.PersistChanges)))
		b.WriteString(fmt.Sprintf("残留痕迹: %d 项\n", len(r.Artifacts)))
		b.WriteString(fmt.Sprintf("认证事件: %d 条\n", len(r.AuthHistory)))
		for i, c := range r.PersistChanges {
			if i >= 5 {
				break
			}
			b.WriteString(fmt.Sprintf("- 持久化变更: [%s] %s → %s (%s)\n", c.Type, c.Path, c.Target, c.ChangeType))
		}
		for i, a := range r.Artifacts {
			if i >= 5 {
				break
			}
			b.WriteString(fmt.Sprintf("- 残留: [%s] %s — %s\n", a.Type, a.Path, a.Reason))
		}
	}

	// Triggerable summary
	if analysis != nil && analysis.Triggerable != nil {
		t := analysis.Triggerable
		b.WriteString("\n## 未来可触发态\n")
		b.WriteString(fmt.Sprintf("自启动: %d 项\n", len(t.Autostarts)))
		b.WriteString(fmt.Sprintf("定时任务: %d 项\n", len(t.Scheduled)))
		b.WriteString(fmt.Sprintf("KeepAlive: %d 项\n", len(t.Keepalive)))
		count := 0
		for _, list := range [][]model.TriggerableEntry{t.Autostarts, t.Scheduled, t.Keepalive} {
			for _, e := range list {
				if len(e.RiskFlags) == 0 {
					continue
				}
				if count >= 10 {
					break
				}
				b.WriteString(fmt.Sprintf("- [%s] %s → %s flags=[%s]\n", e.Type, e.Path, e.Target, strings.Join(e.RiskFlags, ",")))
				count++
			}
		}
	}

	// Timeline high-severity events
	if analysis != nil && len(analysis.Timeline) > 0 {
		var high []model.TimelineEvent
		for _, e := range analysis.Timeline {
			if e.Severity == "high" || e.Severity == "critical" {
				high = append(high, e)
			}
		}
		if len(high) > 0 {
			b.WriteString(fmt.Sprintf("\n## 高严重度时间线事件 (%d)\n", len(high)))
			for i, e := range high {
				if i >= 10 {
					break
				}
				b.WriteString(fmt.Sprintf("- [%s][%s] %s: %s\n", e.Severity, e.Scope, e.Type, e.Summary))
			}
		}
	}

	ctx := b.String()
	if len(ctx) > maxContextChars {
		cut := ctx[:maxContextChars]
		if idx := strings.LastIndex(cut, "\n"); idx > maxContextChars/2 {
			cut = cut[:idx]
		}
		ctx = cut + "\n\n... (数据已截断)"
	}
	return ctx
}
