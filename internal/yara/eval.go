//go:build !yara

package yara

import "strings"

// MatchContext 保存一条规则的全量匹配数据，用于求值 condition AST
type MatchContext struct {
	FileSize int64
	Matches  map[string][]PatternMatch // key = pattern ID (如 "$s1")
}

// buildMatchContext 对一条规则的所有 pattern 在数据中搜索全部匹配位置
func buildMatchContext(data, dataLower []byte, rule *Rule, fileSize int64) *MatchContext {
	ctx := &MatchContext{
		FileSize: fileSize,
		Matches:  make(map[string][]PatternMatch, len(rule.Strings)),
	}
	for i := range rule.Strings {
		pat := &rule.Strings[i]
		ctx.Matches[pat.ID] = findAllMatches(data, dataLower, pat)
	}
	return ctx
}

// EvalCondition 对 AST 求值，返回条件是否满足
func EvalCondition(node CondNode, ctx *MatchContext, rule *Rule) bool {
	if node == nil {
		return true // nil condition = 默认匹配
	}

	switch n := node.(type) {
	case *BoolLiteral:
		return n.Value

	case *StringRef:
		return len(ctx.Matches[n.ID]) > 0

	case *NotExpr:
		return !EvalCondition(n.Operand, ctx, rule)

	case *BinaryBoolExpr:
		left := EvalCondition(n.Left, ctx, rule)
		if n.Op == TokAnd {
			if !left {
				return false // 短路
			}
			return EvalCondition(n.Right, ctx, rule)
		}
		// TokOr
		if left {
			return true // 短路
		}
		return EvalCondition(n.Right, ctx, rule)

	case *CompareExpr:
		// OffsetRef 无匹配时整个比较为 false（YARA "undefined" 语义）
		if isUndefinedOffset(n.Left, ctx) || isUndefinedOffset(n.Right, ctx) {
			return false
		}
		lv := evalInt(n.Left, ctx)
		rv := evalInt(n.Right, ctx)
		switch n.Op {
		case TokLt:
			return lv < rv
		case TokGt:
			return lv > rv
		case TokLe:
			return lv <= rv
		case TokGe:
			return lv >= rv
		case TokEq:
			return lv == rv
		case TokNeq:
			return lv != rv
		}
		return false

	case *OfExpr:
		return evalOf(n, ctx, rule)

	case *AtExpr:
		offset := evalInt(n.Offset, ctx)
		for _, m := range ctx.Matches[n.StringID] {
			if int64(m.Offset) == offset {
				return true
			}
		}
		return false

	case *InExpr:
		low := evalInt(n.Low, ctx)
		high := evalInt(n.High, ctx)
		for _, m := range ctx.Matches[n.StringID] {
			off := int64(m.Offset)
			if off >= low && off <= high {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// evalInt 对产生整数值的节点求值
func evalInt(node CondNode, ctx *MatchContext) int64 {
	switch n := node.(type) {
	case *IntLiteral:
		return n.Value
	case *CountRef:
		return int64(len(ctx.Matches[n.ID]))
	case *OffsetRef:
		matches := ctx.Matches[n.ID]
		if len(matches) == 0 {
			return -1 // 无匹配的哨兵值
		}
		return int64(matches[0].Offset)
	case *FilesizeRef:
		return ctx.FileSize
	default:
		return 0
	}
}

// evalOf 对 "any/all/N of" 表达式求值
func evalOf(n *OfExpr, ctx *MatchContext, rule *Rule) bool {
	ids := resolveStringSet(n.StringSet, rule)

	matchCount := 0
	for _, id := range ids {
		if len(ctx.Matches[id]) > 0 {
			matchCount++
		}
	}

	if n.IsAll {
		return matchCount == len(ids) && len(ids) > 0
	}
	if n.IsAny {
		return matchCount > 0
	}
	// "N of"
	if n.Quantifier != nil {
		required := evalInt(n.Quantifier, ctx)
		return int64(matchCount) >= required
	}
	return matchCount > 0
}

// resolveStringSet 将 StringSet 展开为具体的 pattern ID 列表
// 支持通配符如 "$s*" 匹配 "$s1", "$s2" 等
func resolveStringSet(set []string, rule *Rule) []string {
	if set == nil {
		// "them" = 规则中所有 strings
		ids := make([]string, len(rule.Strings))
		for i, pat := range rule.Strings {
			ids[i] = pat.ID
		}
		return ids
	}

	var result []string
	for _, selector := range set {
		if strings.HasSuffix(selector, "*") {
			prefix := strings.TrimSuffix(selector, "*")
			for _, pat := range rule.Strings {
				if strings.HasPrefix(pat.ID, prefix) {
					result = append(result, pat.ID)
				}
			}
		} else {
			result = append(result, selector)
		}
	}
	return result
}

// isUndefinedOffset 检查节点是否是无匹配的 OffsetRef
func isUndefinedOffset(node CondNode, ctx *MatchContext) bool {
	ref, ok := node.(*OffsetRef)
	if !ok {
		return false
	}
	return len(ctx.Matches[ref.ID]) == 0
}
