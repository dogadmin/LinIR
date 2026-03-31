//go:build !yara

package yara

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
)

// Rule 表示一条解析后的 YARA 规则
type Rule struct {
	Name      string
	Meta      map[string]string
	Strings   []Pattern
	Tags      []string
	Condition CondNode // 解析后的 condition AST（nil = 默认 any of them）
	RawCond   string   // 原始 condition 文本
}

// Pattern 表示一个匹配模式
type Pattern struct {
	ID     string // $s1, $hex1 等
	Value  []byte
	IsHex  bool
	NoCase bool
	Wide   bool
}

// parseYaraFile 解析一个 YARA 规则文件
func parseYaraFile(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0), 1024*1024)

	var current *Rule
	var section string
	var condLines []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		// 规则声明
		if strings.HasPrefix(line, "rule ") {
			r := parseRuleHeader(line)
			current = &r
			section = ""
			condLines = nil
			continue
		}

		if current == nil {
			continue
		}

		// 段标识
		if line == "meta:" {
			section = "meta"
			continue
		}
		if line == "strings:" {
			section = "strings"
			continue
		}
		if strings.HasPrefix(line, "condition:") {
			section = "condition"
			rest := strings.TrimSpace(strings.TrimPrefix(line, "condition:"))
			if rest != "" {
				condLines = append(condLines, rest)
			}
			continue
		}

		// 规则结束
		if line == "}" {
			if current != nil && len(current.Strings) > 0 {
				finalizeRule(current, condLines)
				rules = append(rules, *current)
			}
			current = nil
			section = ""
			condLines = nil
			continue
		}

		switch section {
		case "meta":
			parseMetaLine(current, line)
		case "strings":
			parseStringsLine(current, line)
		case "condition":
			condLines = append(condLines, line)
		}
	}

	return rules, scanner.Err()
}

// finalizeRule 解析 condition 并设置到 Rule 上
func finalizeRule(r *Rule, condLines []string) {
	rawCond := strings.TrimSpace(strings.Join(condLines, " "))
	r.RawCond = rawCond

	if rawCond == "" {
		// 空 condition = any of them（兼容旧行为）
		r.Condition = &OfExpr{IsAny: true}
		return
	}

	node, _ := ParseCondition(rawCond)
	// 即使有 warning 也使用解析结果——parser 在遇到不支持的特性时
	// 已经对不可解析的部分插入了 BoolLiteral{true} 安全回退
	r.Condition = node
}

func parseRuleHeader(line string) Rule {
	r := Rule{Meta: make(map[string]string)}
	line = strings.TrimPrefix(line, "rule ")
	line = strings.TrimSuffix(line, "{")
	line = strings.TrimSpace(line)

	if colonIdx := strings.Index(line, ":"); colonIdx >= 0 {
		r.Name = strings.TrimSpace(line[:colonIdx])
		tagsPart := strings.TrimSpace(line[colonIdx+1:])
		r.Tags = strings.Fields(tagsPart)
	} else {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			r.Name = fields[0]
		}
	}
	return r
}

func parseMetaLine(r *Rule, line string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, "\"")
	r.Meta[key] = val
}

func parseStringsLine(r *Rule, line string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	id := strings.TrimSpace(parts[0])
	rest := strings.TrimSpace(parts[1])

	pat := Pattern{ID: id}

	if strings.HasPrefix(rest, "{") {
		hexStr := strings.TrimPrefix(rest, "{")
		hexStr = strings.TrimSuffix(hexStr, "}")
		hexStr = strings.TrimSpace(hexStr)
		hexStr = strings.ReplaceAll(hexStr, " ", "")
		hexStr = strings.ReplaceAll(hexStr, "??", "00")
		decoded, err := hex.DecodeString(hexStr)
		if err == nil {
			pat.Value = decoded
			pat.IsHex = true
		}
	} else if strings.HasPrefix(rest, "\"") {
		endQuote := strings.Index(rest[1:], "\"")
		if endQuote < 0 {
			return
		}
		pat.Value = []byte(rest[1 : endQuote+1])
		modifiers := rest[endQuote+2:]
		if strings.Contains(modifiers, "nocase") {
			pat.NoCase = true
		}
		if strings.Contains(modifiers, "wide") {
			pat.Wide = true
		}
	} else {
		return
	}

	if len(pat.Value) > 0 {
		r.Strings = append(r.Strings, pat)
	}
}
