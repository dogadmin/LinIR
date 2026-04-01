//go:build linux

package watch

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/dogadmin/LinIR/internal/model"
)

// ConntrackMonitor 通过 Linux conntrack 事件实时监控网络连接。
// 相比轮询 /proc/net/tcp，conntrack 的优势：
//   - 事件驱动，不遗漏短暂连接（即使收到 RST，条目保留 10 秒）
//   - 抓到 SYN_SENT 阶段的连接（轮询可能在 ESTABLISHED 之前就结束）
//
// 前提：nf_conntrack 内核模块已加载。需要 CAP_NET_ADMIN 权限。
type ConntrackMonitor struct {
	iocStore *IOCStore
	events   chan HitEvent
}

// NewConntrackMonitor 创建 conntrack 监控器（iface 参数在 Linux 上不使用，conntrack 监听所有接口）
func NewConntrackMonitor(store *IOCStore, iface string) *ConntrackMonitor {
	return &ConntrackMonitor{
		iocStore: store,
		events:   make(chan HitEvent, 256),
	}
}

// Events 返回命中事件的 channel
func (m *ConntrackMonitor) Events() <-chan HitEvent {
	return m.events
}

// Run 启动 conntrack 事件监听，阻塞直到 ctx 取消
func (m *ConntrackMonitor) Run(ctx context.Context) error {
	conn, err := ct.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack dial: %w (是否已加载 nf_conntrack 模块?)", err)
	}
	defer conn.Close()

	evCh := make(chan ct.Event, 1024)
	errCh, err := conn.Listen(evCh, 4, []netfilter.NetlinkGroup{netfilter.GroupCTNew})
	if err != nil {
		return fmt.Errorf("conntrack listen: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return fmt.Errorf("conntrack error: %w", err)
		case ev := <-evCh:
			m.handleEvent(ev)
		}
	}
}

func (m *ConntrackMonitor) handleEvent(ev ct.Event) {
	if ev.Flow == nil {
		return
	}

	// 只关注 TCP 和 UDP
	proto := ev.Flow.TupleOrig.Proto.Protocol
	if proto != 6 && proto != 17 { // TCP=6, UDP=17
		return
	}

	srcIP := ev.Flow.TupleOrig.IP.SourceAddress
	dstIP := ev.Flow.TupleOrig.IP.DestinationAddress
	dstPort := ev.Flow.TupleOrig.Proto.DestinationPort
	srcPort := ev.Flow.TupleOrig.Proto.SourcePort

	protoStr := "tcp"
	if proto == 17 {
		protoStr = "udp"
	}

	now := time.Now()

	// 检查目标 IP 是否命中 IOC（出站连接）
	if ioc, ok := m.iocStore.MatchIP(dstIP.String()); ok {
		conn := model.ConnectionInfo{
			Proto:         protoStr,
			Family:        addrFamily(dstIP),
			LocalAddress:  srcIP.String(),
			LocalPort:     srcPort,
			RemoteAddress: dstIP.String(),
			RemotePort:    dstPort,
			Source:        "conntrack",
			Confidence:    "high",
			State:         "NEW",
		}
		m.events <- HitEvent{
			Timestamp:  now,
			IOC:        ioc,
			MatchType:  "direct_ip",
			Connection: conn,
		}
		return
	}

	// 检查源 IP 是否命中 IOC（入站连接）
	if ioc, ok := m.iocStore.MatchIP(srcIP.String()); ok {
		conn := model.ConnectionInfo{
			Proto:         protoStr,
			Family:        addrFamily(srcIP),
			LocalAddress:  dstIP.String(),
			LocalPort:     dstPort,
			RemoteAddress: srcIP.String(),
			RemotePort:    srcPort,
			Source:        "conntrack",
			Confidence:    "high",
			State:         "NEW",
		}
		m.events <- HitEvent{
			Timestamp:  now,
			IOC:        ioc,
			MatchType:  "direct_ip",
			Connection: conn,
		}
	}
}

func addrFamily(ip netip.Addr) string {
	if ip.Is4() || ip.Is4In6() {
		return "ipv4"
	}
	return "ipv6"
}

// ConntrackAvailable 检查 conntrack 是否可用
func ConntrackAvailable() bool {
	conn, err := ct.Dial(nil)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
