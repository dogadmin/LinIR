//go:build !yara

package yara

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// Available 报告 YARA 扫描是否可用
func Available() bool { return true }

// Scanner 是纯 Go 实现的 YARA 扫描器
// 支持 condition 子集：and/or/not, any/all/N of, #count, @offset, filesize, at, in
type Scanner struct {
	rules     []Rule
	hasNocase bool
}

// NewScanner 从指定路径加载 YARA 规则
func NewScanner(rulesPath string) (*Scanner, error) {
	if rulesPath == "" {
		return nil, fmt.Errorf("规则路径不能为空")
	}

	s := &Scanner{}

	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("访问规则路径 %s: %w", rulesPath, err)
	}

	if info.IsDir() {
		err = filepath.Walk(rulesPath, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yar" || ext == ".yara" || ext == ".rule" {
				rules, parseErr := parseYaraFile(path)
				if parseErr == nil {
					s.rules = append(s.rules, rules...)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		rules, err := parseYaraFile(rulesPath)
		if err != nil {
			return nil, err
		}
		s.rules = rules
	}

	if len(s.rules) == 0 {
		return nil, fmt.Errorf("未从 %s 加载到任何规则", rulesPath)
	}

	// 预计算是否有 nocase 模式
	for _, rule := range s.rules {
		for _, pat := range rule.Strings {
			if pat.NoCase {
				s.hasNocase = true
				break
			}
		}
		if s.hasNocase {
			break
		}
	}

	return s, nil
}

// RuleCount 返回加载的规则数量
func (s *Scanner) RuleCount() int {
	return len(s.rules)
}

// ScanFile 扫描单个文件
func (s *Scanner) ScanFile(ctx context.Context, path string) ([]model.YaraHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxSize = 50 * 1024 * 1024 // 50MB
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, nil
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return s.matchData(ctx, data, path)
}

// ScanDir 递归扫描目录
func (s *Scanner) ScanDir(ctx context.Context, dir string) ([]model.YaraHit, error) {
	var allHits []model.YaraHit
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if info.IsDir() || info.Size() == 0 {
			return nil
		}
		hits, scanErr := s.ScanFile(ctx, path)
		if scanErr == nil {
			allHits = append(allHits, hits...)
		}
		return nil
	})
	return allHits, err
}

// matchData 是核心匹配逻辑：对每条规则做全量模式搜索，然后求值 condition AST
func (s *Scanner) matchData(ctx context.Context, data []byte, filePath string) ([]model.YaraHit, error) {
	var hits []model.YaraHit
	var dataLower []byte
	if s.hasNocase {
		dataLower = bytesToLower(data)
	}

	fileSize := int64(len(data))

	for i := range s.rules {
		rule := &s.rules[i]

		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}

		// Phase 1: 全量模式搜索，记录所有匹配偏移
		mctx := buildMatchContext(data, dataLower, rule, fileSize)

		// Phase 2: 求值 condition AST
		matched := EvalCondition(rule.Condition, mctx, rule)

		if matched {
			var matchedStrings []string
			for _, pat := range rule.Strings {
				if len(mctx.Matches[pat.ID]) > 0 {
					matchedStrings = append(matchedStrings, pat.ID)
				}
			}
			hit := model.YaraHit{
				Rule:         rule.Name,
				TargetType:   "file",
				TargetPath:   filePath,
				Meta:         rule.Meta,
				Strings:      matchedStrings,
				SeverityHint: rule.Meta["severity"],
			}
			hits = append(hits, hit)
		}
	}

	return hits, nil
}
