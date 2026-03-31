//go:build !yara

package yara

import "bytes"

// PatternMatch 记录一次模式匹配的位置
type PatternMatch struct {
	Offset int
	Length int
}

// findAllMatches 在数据中搜索一个 pattern 的所有出现位置
func findAllMatches(data, dataLower []byte, pat *Pattern) []PatternMatch {
	search := data
	value := pat.Value

	if pat.NoCase {
		search = dataLower
		value = bytesToLower(pat.Value)
	}

	if pat.Wide {
		value = toWide(value)
	}

	return findAllOccurrences(search, value)
}

// findAllOccurrences 返回 needle 在 haystack 中所有出现的偏移（允许重叠，符合 YARA 语义）
// 使用 bytes.Index (stdlib Rabin-Karp) 实现 O(n) 平均性能
func findAllOccurrences(haystack, needle []byte) []PatternMatch {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return nil
	}
	var results []PatternMatch
	offset := 0
	for {
		idx := bytes.Index(haystack[offset:], needle)
		if idx < 0 {
			break
		}
		absOffset := offset + idx
		results = append(results, PatternMatch{
			Offset: absOffset,
			Length: len(needle),
		})
		offset = absOffset + 1 // 允许重叠
	}
	return results
}

// toWide 将 ASCII 字节转为 UTF-16LE（wide）编码
func toWide(b []byte) []byte {
	wide := make([]byte, len(b)*2)
	for i, c := range b {
		wide[i*2] = c
		wide[i*2+1] = 0
	}
	return wide
}

// containsBytes 检查 data 中是否包含 pattern（兼容旧接口）
func containsBytes(data, pattern []byte) bool {
	return bytes.Contains(data, pattern)
}

// bytesToLower 将字节数组中的大写 ASCII 转为小写
func bytesToLower(data []byte) []byte {
	lower := make([]byte, len(data))
	for i, b := range data {
		if b >= 'A' && b <= 'Z' {
			lower[i] = b + 32
		} else {
			lower[i] = b
		}
	}
	return lower
}
