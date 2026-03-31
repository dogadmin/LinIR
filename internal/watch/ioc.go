package watch

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// IOCStore 存储和索引 IOC 列表
type IOCStore struct {
	ips     map[string]IOC // key = normalized IP
	domains map[string]IOC // key = lowercase domain
	total   int
}

// LoadIOCFile 从文件加载 IOC 列表。
// 支持格式：每行一个 IOC，自动识别 IP/域名，支持 # 注释和空行。
// 支持可选 tag：1.2.3.4 tag1,tag2
func LoadIOCFile(path string) (*IOCStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 IOC 文件: %w", err)
	}
	defer f.Close()

	store := &IOCStore{
		ips:     make(map[string]IOC),
		domains: make(map[string]IOC),
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// 解析: value [tags]
		parts := strings.Fields(line)
		value := parts[0]
		var tags []string
		if len(parts) > 1 {
			tags = strings.Split(parts[1], ",")
		}

		// 识别类型
		if ip := net.ParseIP(value); ip != nil {
			normalized := ip.String()
			store.ips[normalized] = IOC{
				Type:  "ip",
				Value: normalized,
				Tags:  tags,
			}
		} else if isValidDomain(value) {
			lower := strings.ToLower(value)
			store.domains[lower] = IOC{
				Type:  "domain",
				Value: lower,
				Tags:  tags,
			}
		}
		// 跳过无法识别的行
	}

	store.total = len(store.ips) + len(store.domains)
	if store.total == 0 {
		return nil, fmt.Errorf("IOC 文件 %s 中未找到有效 IOC", path)
	}

	return store, scanner.Err()
}

// MatchIP 检查 IP 是否命中 IOC
func (s *IOCStore) MatchIP(ip string) (IOC, bool) {
	// 标准化 IP
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return IOC{}, false
	}
	ioc, ok := s.ips[parsed.String()]
	return ioc, ok
}

// MatchDomain 检查域名是否命中 IOC
func (s *IOCStore) MatchDomain(domain string) (IOC, bool) {
	lower := strings.ToLower(domain)
	ioc, ok := s.domains[lower]
	return ioc, ok
}

// Total 返回 IOC 总数
func (s *IOCStore) Total() int {
	return s.total
}

// IPCount 返回 IP IOC 数量
func (s *IOCStore) IPCount() int {
	return len(s.ips)
}

// DomainCount 返回 Domain IOC 数量
func (s *IOCStore) DomainCount() int {
	return len(s.domains)
}

// isValidDomain 简单校验是否为合法域名
func isValidDomain(s string) bool {
	if len(s) < 3 || !strings.Contains(s, ".") {
		return false
	}
	// 排除 IP 地址
	if net.ParseIP(s) != nil {
		return false
	}
	// 排除包含非法字符
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
