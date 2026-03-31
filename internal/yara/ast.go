//go:build !yara

package yara

// CondNode 是 condition 表达式 AST 的节点接口
type CondNode interface {
	condNode()
}

// BoolLiteral: true / false
type BoolLiteral struct{ Value bool }

// StringRef: $s1 — 该 pattern 是否至少匹配一次
type StringRef struct{ ID string }

// CountRef: #s1 — 该 pattern 匹配的次数
type CountRef struct{ ID string }

// OffsetRef: @s1 — 该 pattern 首次匹配的偏移
type OffsetRef struct{ ID string }

// FilesizeRef: filesize — 文件字节大小
type FilesizeRef struct{}

// IntLiteral: 100, 0x1000, 1MB
type IntLiteral struct{ Value int64 }

// NotExpr: not <expr>
type NotExpr struct{ Operand CondNode }

// BinaryBoolExpr: <expr> and/or <expr>
type BinaryBoolExpr struct {
	Op    TokenKind // TokAnd 或 TokOr
	Left  CondNode
	Right CondNode
}

// CompareExpr: <expr> <op> <expr>  (用于 #s1 > 3, filesize < 1MB 等)
type CompareExpr struct {
	Op    TokenKind // TokLt, TokGt, TokLe, TokGe, TokEq, TokNeq
	Left  CondNode
	Right CondNode
}

// OfExpr: any/all/N of them 或 any/all/N of ($s*)
type OfExpr struct {
	Quantifier CondNode // IntLiteral（"N of"），nil 表示 any/all
	IsAny      bool
	IsAll      bool
	StringSet  []string // nil = "them"（所有 strings）；否则显式列表如 ["$s*"]
}

// AtExpr: $s1 at 0
type AtExpr struct {
	StringID string
	Offset   CondNode
}

// InExpr: $s1 in (0..1024)
type InExpr struct {
	StringID string
	Low      CondNode
	High     CondNode
}

// 标记方法实现
func (BoolLiteral) condNode()     {}
func (StringRef) condNode()       {}
func (CountRef) condNode()        {}
func (OffsetRef) condNode()       {}
func (FilesizeRef) condNode()     {}
func (IntLiteral) condNode()      {}
func (NotExpr) condNode()         {}
func (BinaryBoolExpr) condNode()  {}
func (CompareExpr) condNode()     {}
func (OfExpr) condNode()          {}
func (AtExpr) condNode()          {}
func (InExpr) condNode()          {}
