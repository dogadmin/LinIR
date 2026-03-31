//go:build !yara

package yara

import (
	"fmt"
	"strings"
)

// 优先级常量（越高绑定越紧）
const (
	precOr      = 1
	precAnd     = 2
	precCompare = 3
)

// CondParser 将 condition 字符串解析为 AST
type CondParser struct {
	lex    *Lexer
	cur    Token
	errors []string
}

// NewCondParser 创建 condition 解析器
func NewCondParser(condition string) *CondParser {
	p := &CondParser{lex: NewLexer(condition)}
	p.advance()
	return p
}

// Parse 解析完整的 condition 表达式
// 解析失败时返回 BoolLiteral{true} 作为安全回退（保持 "any string hit" 旧行为）
func (p *CondParser) Parse() (CondNode, []string) {
	if p.cur.Kind == TokEOF {
		return &BoolLiteral{Value: true}, nil
	}
	node := p.parseExpr(0)
	return node, p.errors
}

func (p *CondParser) advance() Token {
	prev := p.cur
	p.cur = p.lex.NextToken()
	return prev
}

func (p *CondParser) expect(kind TokenKind) Token {
	if p.cur.Kind != kind {
		p.errors = append(p.errors, fmt.Sprintf("pos %d: 期望 %d 但得到 %q", p.cur.Pos, kind, p.cur.Literal))
	}
	return p.advance()
}

// parseExpr 使用 Pratt 优先级爬升解析表达式
func (p *CondParser) parseExpr(minPrec int) CondNode {
	left := p.parsePrimary()

	for {
		prec := infixPrec(p.cur.Kind)
		if prec < minPrec || prec == 0 {
			break
		}

		op := p.advance()

		switch op.Kind {
		case TokAnd, TokOr:
			right := p.parseExpr(prec + 1)
			left = &BinaryBoolExpr{Op: op.Kind, Left: left, Right: right}

		case TokLt, TokGt, TokLe, TokGe, TokEq, TokNeq:
			right := p.parseExpr(prec + 1)
			left = &CompareExpr{Op: op.Kind, Left: left, Right: right}

		default:
			p.errors = append(p.errors, fmt.Sprintf("pos %d: 未知中缀运算符 %q", op.Pos, op.Literal))
			return left
		}
	}

	return left
}

// parsePrimary 解析原子表达式
func (p *CondParser) parsePrimary() CondNode {
	switch p.cur.Kind {
	case TokNot:
		p.advance()
		operand := p.parsePrimary()
		return &NotExpr{Operand: operand}

	case TokStringID:
		id := p.advance().Literal
		// 检查后续是否有 at / in
		if p.cur.Kind == TokAt {
			p.advance()
			offset := p.parsePrimary()
			return &AtExpr{StringID: id, Offset: offset}
		}
		if p.cur.Kind == TokIn {
			p.advance()
			return p.parseInExpr(id)
		}
		return &StringRef{ID: id}

	case TokCountID:
		id := p.advance().Literal
		return &CountRef{ID: id}

	case TokOffsetID:
		id := p.advance().Literal
		return &OffsetRef{ID: id}

	case TokFilesize:
		p.advance()
		return &FilesizeRef{}

	case TokInteger:
		tok := p.advance()
		// 检查是否是 "N of"
		if p.cur.Kind == TokOf {
			p.advance()
			return p.parseOfBody(&IntLiteral{Value: tok.IntVal}, false, false)
		}
		return &IntLiteral{Value: tok.IntVal}

	case TokTrue:
		p.advance()
		return &BoolLiteral{Value: true}

	case TokFalse:
		p.advance()
		return &BoolLiteral{Value: false}

	case TokAny:
		p.advance()
		p.expect(TokOf)
		return p.parseOfBody(nil, true, false)

	case TokAll:
		p.advance()
		p.expect(TokOf)
		return p.parseOfBody(nil, false, true)

	case TokLParen:
		p.advance()
		expr := p.parseExpr(0)
		p.expect(TokRParen)
		return expr

	case TokEOF:
		return &BoolLiteral{Value: true}

	default:
		p.errors = append(p.errors, fmt.Sprintf("pos %d: 不支持的 token %q", p.cur.Pos, p.cur.Literal))
		p.advance()
		return &BoolLiteral{Value: true}
	}
}

// parseOfBody 解析 "of" 之后的部分: "them" 或 "($s1, $s2)" 或 "($s*)"
func (p *CondParser) parseOfBody(quant CondNode, isAny, isAll bool) CondNode {
	of := &OfExpr{
		Quantifier: quant,
		IsAny:      isAny,
		IsAll:      isAll,
	}

	if p.cur.Kind == TokThem {
		p.advance()
		of.StringSet = nil // nil = "them"（所有 strings）
		return of
	}

	if p.cur.Kind == TokLParen {
		p.advance()
		var ids []string
		for p.cur.Kind != TokRParen && p.cur.Kind != TokEOF {
			if p.cur.Kind == TokStringID {
				id := p.advance().Literal
				// 支持 $s* 通配符
				if p.cur.Kind == TokEOF || p.cur.Kind == TokRParen || p.cur.Kind == TokComma {
					ids = append(ids, id)
				}
			} else {
				// 可能是 $s* 里的 * 被 lexer 吃掉了，尝试恢复
				p.advance()
			}
			if p.cur.Kind == TokComma {
				p.advance()
			}
		}
		p.expect(TokRParen)

		// 处理通配符：检查原始 condition 文本中是否有 *
		// 在 lexer 层面 * 没有被识别，但 $ 开头的 ID 后面可能跟了 *
		// 这里的 ids 已经是 lexer 输出的 $identifier，通配符需要在 rule.go 解析时处理
		of.StringSet = ids
		return of
	}

	// 回退: 无法解析 of 的目标
	p.errors = append(p.errors, fmt.Sprintf("pos %d: 'of' 后期望 'them' 或 '(...)'", p.cur.Pos))
	of.StringSet = nil
	return of
}

// parseInExpr 解析 "in (low..high)"
func (p *CondParser) parseInExpr(stringID string) CondNode {
	p.expect(TokLParen)
	low := p.parsePrimary()
	p.expect(TokDotDot)
	high := p.parsePrimary()
	p.expect(TokRParen)
	return &InExpr{StringID: stringID, Low: low, High: high}
}

func infixPrec(kind TokenKind) int {
	switch kind {
	case TokOr:
		return precOr
	case TokAnd:
		return precAnd
	case TokLt, TokGt, TokLe, TokGe, TokEq, TokNeq:
		return precCompare
	}
	return 0
}

// ParseCondition 是便捷函数：解析 condition 字符串，返回 AST 和警告
// 如果 condition 为空，返回 "any of them" 默认行为
func ParseCondition(condition string) (CondNode, []string) {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return &OfExpr{IsAny: true}, nil
	}
	p := NewCondParser(condition)
	return p.Parse()
}
