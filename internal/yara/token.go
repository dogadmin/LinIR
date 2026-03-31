//go:build !yara

package yara

import (
	"strings"
	"unicode"
)

// TokenKind 表示 token 类型
type TokenKind int

const (
	TokEOF TokenKind = iota
	TokStringID      // $s1
	TokCountID       // #s1
	TokOffsetID      // @s1
	TokInteger       // 123, 0x1000, 1MB
	TokFilesize      // filesize
	TokTrue          // true
	TokFalse         // false
	TokAnd           // and
	TokOr            // or
	TokNot           // not
	TokAll           // all
	TokAny           // any
	TokOf            // of
	TokThem          // them
	TokAt            // at
	TokIn            // in
	TokEq            // ==
	TokNeq           // !=
	TokLt            // <
	TokGt            // >
	TokLe            // <=
	TokGe            // >=
	TokLParen        // (
	TokRParen        // )
	TokDotDot        // ..
	TokComma         // ,
)

// Token 表示一个词法单元
type Token struct {
	Kind    TokenKind
	Literal string
	IntVal  int64
	Pos     int
}

// Lexer 对 condition 字符串进行词法分析
type Lexer struct {
	input []rune
	pos   int
}

// NewLexer 创建新的词法分析器
func NewLexer(input string) *Lexer {
	return &Lexer{input: []rune(input), pos: 0}
}

// NextToken 返回下一个 token
func (l *Lexer) NextToken() Token {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return Token{Kind: TokEOF, Pos: l.pos}
	}

	start := l.pos
	ch := l.input[l.pos]

	switch {
	case ch == '$':
		return l.readPrefixedID(TokStringID, start)
	case ch == '#':
		return l.readPrefixedID(TokCountID, start)
	case ch == '@':
		return l.readPrefixedID(TokOffsetID, start)
	case ch == '(':
		l.pos++
		return Token{Kind: TokLParen, Literal: "(", Pos: start}
	case ch == ')':
		l.pos++
		return Token{Kind: TokRParen, Literal: ")", Pos: start}
	case ch == ',':
		l.pos++
		return Token{Kind: TokComma, Literal: ",", Pos: start}
	case ch == '.' && l.peek() == '.':
		l.pos += 2
		return Token{Kind: TokDotDot, Literal: "..", Pos: start}
	case ch == '=' && l.peek() == '=':
		l.pos += 2
		return Token{Kind: TokEq, Literal: "==", Pos: start}
	case ch == '!' && l.peek() == '=':
		l.pos += 2
		return Token{Kind: TokNeq, Literal: "!=", Pos: start}
	case ch == '<' && l.peek() == '=':
		l.pos += 2
		return Token{Kind: TokLe, Literal: "<=", Pos: start}
	case ch == '>' && l.peek() == '=':
		l.pos += 2
		return Token{Kind: TokGe, Literal: ">=", Pos: start}
	case ch == '<':
		l.pos++
		return Token{Kind: TokLt, Literal: "<", Pos: start}
	case ch == '>':
		l.pos++
		return Token{Kind: TokGt, Literal: ">", Pos: start}
	case ch >= '0' && ch <= '9':
		return l.readInteger(start)
	case unicode.IsLetter(ch) || ch == '_':
		return l.readKeywordOrIdent(start)
	default:
		// 跳过未知字符
		l.pos++
		return l.NextToken()
	}
}

// PeekToken 查看下一个 token 但不消费
func (l *Lexer) PeekToken() Token {
	savedPos := l.pos
	tok := l.NextToken()
	l.pos = savedPos
	return tok
}

func (l *Lexer) peek() rune {
	if l.pos+1 >= len(l.input) {
		return 0
	}
	return l.input[l.pos+1]
}

func (l *Lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(l.input[l.pos]) {
		l.pos++
	}
}

// readPrefixedID 读取 $name / #name / @name，包括尾随的 * 通配符
func (l *Lexer) readPrefixedID(kind TokenKind, start int) Token {
	l.pos++ // 跳过 $ / # / @
	idStart := l.pos
	for l.pos < len(l.input) && isIdentChar(l.input[l.pos]) {
		l.pos++
	}
	// 包含尾随 * 通配符（用于 "any of ($s*)" 语法）
	if l.pos < len(l.input) && l.input[l.pos] == '*' {
		l.pos++
	}
	// 对 # 和 @，存储时转为 $ 前缀以统一查找
	id := "$" + string(l.input[idStart:l.pos])
	return Token{Kind: kind, Literal: id, Pos: start}
}

// readInteger 读取整数字面量，支持 0x 前缀和 KB/MB/GB 后缀
func (l *Lexer) readInteger(start int) Token {
	var val int64

	if l.input[l.pos] == '0' && l.pos+1 < len(l.input) && (l.input[l.pos+1] == 'x' || l.input[l.pos+1] == 'X') {
		// 十六进制
		l.pos += 2
		for l.pos < len(l.input) && isHexDigit(l.input[l.pos]) {
			val = val*16 + hexVal(l.input[l.pos])
			l.pos++
		}
	} else {
		// 十进制
		for l.pos < len(l.input) && l.input[l.pos] >= '0' && l.input[l.pos] <= '9' {
			val = val*10 + int64(l.input[l.pos]-'0')
			l.pos++
		}
	}

	// 检查 KB/MB/GB 后缀
	rest := string(l.input[l.pos:])
	upper := strings.ToUpper(rest)
	if strings.HasPrefix(upper, "KB") {
		val *= 1024
		l.pos += 2
	} else if strings.HasPrefix(upper, "MB") {
		val *= 1024 * 1024
		l.pos += 2
	} else if strings.HasPrefix(upper, "GB") {
		val *= 1024 * 1024 * 1024
		l.pos += 2
	}

	lit := string(l.input[start:l.pos])
	return Token{Kind: TokInteger, Literal: lit, IntVal: val, Pos: start}
}

// readKeywordOrIdent 读取关键字
func (l *Lexer) readKeywordOrIdent(start int) Token {
	for l.pos < len(l.input) && isIdentChar(l.input[l.pos]) {
		l.pos++
	}
	word := string(l.input[start:l.pos])

	switch word {
	case "and":
		return Token{Kind: TokAnd, Literal: word, Pos: start}
	case "or":
		return Token{Kind: TokOr, Literal: word, Pos: start}
	case "not":
		return Token{Kind: TokNot, Literal: word, Pos: start}
	case "all":
		return Token{Kind: TokAll, Literal: word, Pos: start}
	case "any":
		return Token{Kind: TokAny, Literal: word, Pos: start}
	case "of":
		return Token{Kind: TokOf, Literal: word, Pos: start}
	case "them":
		return Token{Kind: TokThem, Literal: word, Pos: start}
	case "at":
		return Token{Kind: TokAt, Literal: word, Pos: start}
	case "in":
		return Token{Kind: TokIn, Literal: word, Pos: start}
	case "filesize":
		return Token{Kind: TokFilesize, Literal: word, Pos: start}
	case "true":
		return Token{Kind: TokTrue, Literal: word, Pos: start}
	case "false":
		return Token{Kind: TokFalse, Literal: word, Pos: start}
	default:
		// 未知标识符——当作 integer 0 处理（容错）
		return Token{Kind: TokInteger, Literal: word, IntVal: 0, Pos: start}
	}
}

func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}

func isHexDigit(ch rune) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

func hexVal(ch rune) int64 {
	switch {
	case ch >= '0' && ch <= '9':
		return int64(ch - '0')
	case ch >= 'a' && ch <= 'f':
		return int64(ch-'a') + 10
	case ch >= 'A' && ch <= 'F':
		return int64(ch-'A') + 10
	}
	return 0
}
