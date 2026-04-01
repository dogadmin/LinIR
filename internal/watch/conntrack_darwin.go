//go:build darwin

package watch

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// ConntrackMonitor 在 macOS 上通过 BPF (/dev/bpf) 捕获 TCP SYN 包实现实时连接监控。
// 与 Wireshark 使用相同的底层机制，纯 Go 实现，无需 CGO。
//
// 工作原理：
//   1. 打开 /dev/bpfX 设备
//   2. 绑定到主网络接口
//   3. 安装内核级 BPF 过滤器，只捕获 TCP SYN 包（非 SYN-ACK）
//   4. 从每个 SYN 包提取源/目标 IP 和端口
//   5. 与 IOC 列表比对
//
// 需要 root/sudo 权限。
type ConntrackMonitor struct {
	iocStore  *IOCStore
	events    chan HitEvent
	ifaceName string // 用户指定的接口名，空=自动检测
	metrics   *WatchMetrics
}

func NewConntrackMonitor(store *IOCStore, iface string, metrics *WatchMetrics) *ConntrackMonitor {
	return &ConntrackMonitor{
		iocStore:  store,
		events:    make(chan HitEvent, 4096),
		ifaceName: iface,
		metrics:   metrics,
	}
}

func (m *ConntrackMonitor) Events() <-chan HitEvent {
	return m.events
}

// Run 启动 BPF 包捕获，阻塞直到 ctx 取消
func (m *ConntrackMonitor) Run(ctx context.Context) error {
	// 1. 打开 BPF 设备
	fd, err := openBPF()
	if err != nil {
		return fmt.Errorf("BPF: %w", err)
	}
	defer unix.Close(fd)

	// 2. 获取接口名（用户指定或自动检测）
	ifName := m.ifaceName
	if ifName == "" {
		var err2 error
		ifName, err2 = defaultInterface()
		if err2 != nil {
			return fmt.Errorf("获取默认网络接口: %w", err2)
		}
	}

	// 3. 绑定到接口
	fmt.Printf("[INFO] BPF: 绑定接口 %s\n", ifName)
	if err := bindBPF(fd, ifName); err != nil {
		return fmt.Errorf("BPF 绑定 %s: %w", ifName, err)
	}

	// 4. 设置即时模式
	if err := setImmediate(fd); err != nil {
		return fmt.Errorf("BPF immediate: %w", err)
	}

	// 5. 安装 SYN-only 过滤器
	if err := installSYNFilter(fd); err != nil {
		return fmt.Errorf("BPF 过滤器: %w", err)
	}

	// 6. 获取 buffer 大小
	bufLen, err := getBufLen(fd)
	if err != nil {
		return fmt.Errorf("BPF buflen: %w", err)
	}

	buf := make([]byte, bufLen)

	// 7. 设置读超时（只需一次）
	tv := unix.Timeval{Sec: 1}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// 8. 读取循环
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR || os.IsTimeout(err) {
				continue
			}
			return fmt.Errorf("BPF read: %w", err)
		}
		if n <= 0 {
			continue
		}

		m.processBPFBuffer(buf[:n])
	}
}

// processBPFBuffer 解析 BPF buffer 中的多个包
func (m *ConntrackMonitor) processBPFBuffer(buf []byte) {
	// BPF buffer 包含多个帧，每帧前面是 bpf_hdr:
	//   u32 bh_tstamp_sec
	//   u32 bh_tstamp_usec
	//   u32 bh_caplen   (捕获长度)
	//   u32 bh_datalen  (原始长度)
	//   u16 bh_hdrlen   (header 长度，含 padding)
	const minBPFHdr = 18

	pos := 0
	for pos+minBPFHdr <= len(buf) {
		capLen := binary.LittleEndian.Uint32(buf[pos+8 : pos+12])
		hdrLen := binary.LittleEndian.Uint16(buf[pos+16 : pos+18])

		dataStart := pos + int(hdrLen)
		dataEnd := dataStart + int(capLen)
		if dataEnd > len(buf) {
			break
		}

		m.processPacket(buf[dataStart:dataEnd])

		// BPF_WORDALIGN: 下一帧对齐到 4 字节边界
		total := int(hdrLen) + int(capLen)
		total = (total + 3) &^ 3
		pos += total
	}
}

// processPacket 解析单个以太网帧，提取 TCP SYN 的 IP 信息
func (m *ConntrackMonitor) processPacket(pkt []byte) {
	if len(pkt) < 14 {
		return
	}

	// 以太网帧: dst(6) + src(6) + ethertype(2)
	etherType := binary.BigEndian.Uint16(pkt[12:14])

	switch etherType {
	case 0x0800: // IPv4
		m.processIPv4(pkt[14:])
	case 0x86DD: // IPv6
		m.processIPv6(pkt[14:])
	}
}

func (m *ConntrackMonitor) processIPv4(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	// IP 协议
	if pkt[9] != 6 { // TCP
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return
	}

	srcIP := net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	dstIP := net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])

	tcp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	m.matchAndEmit(srcIP, dstIP, srcPort, dstPort, "ipv4")
}

func (m *ConntrackMonitor) processIPv6(pkt []byte) {
	if len(pkt) < 40 {
		return
	}
	// Next Header
	if pkt[6] != 6 { // TCP (简化：不处理扩展头)
		return
	}

	srcIP := make(net.IP, 16)
	dstIP := make(net.IP, 16)
	copy(srcIP, pkt[8:24])
	copy(dstIP, pkt[24:40])

	tcp := pkt[40:]
	if len(tcp) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	m.matchAndEmit(srcIP, dstIP, srcPort, dstPort, "ipv6")
}

func (m *ConntrackMonitor) matchAndEmit(srcIP, dstIP net.IP, srcPort, dstPort uint16, family string) {
	now := time.Now()

	// 出站: 目标 IP 命中 IOC
	if ioc, ok := m.iocStore.MatchIP(dstIP.String()); ok {
		m.emit(HitEvent{
			Timestamp:   now,
			IOC:         ioc,
			MatchType:   "direct_ip",
			SourceStage: "bpf_syn",
			Connection: model.ConnectionInfo{
				Proto:         "tcp",
				Family:        family,
				LocalAddress:  srcIP.String(),
				LocalPort:     srcPort,
				RemoteAddress: dstIP.String(),
				RemotePort:    dstPort,
				Source:        "bpf_syn",
				Confidence:    "high",
				State:         "SYN_SENT",
			},
		})
		return
	}

	// 入站: 源 IP 命中 IOC
	if ioc, ok := m.iocStore.MatchIP(srcIP.String()); ok {
		m.emit(HitEvent{
			Timestamp:   now,
			IOC:         ioc,
			MatchType:   "direct_ip",
			SourceStage: "bpf_syn",
			Connection: model.ConnectionInfo{
				Proto:         "tcp",
				Family:        family,
				LocalAddress:  dstIP.String(),
				LocalPort:     dstPort,
				RemoteAddress: srcIP.String(),
				RemotePort:    srcPort,
				Source:        "bpf_syn",
				Confidence:    "high",
				State:         "SYN_SENT",
			},
		})
	}
}

// emit 非阻塞发送命中事件
func (m *ConntrackMonitor) emit(hit HitEvent) {
	if m.metrics != nil {
		m.metrics.RawEventsTotal.Add(1)
		m.metrics.IOCMatchedTotal.Add(1)
	}
	select {
	case m.events <- hit:
	default:
		if m.metrics != nil {
			m.metrics.EventChannelOverflow.Add(1)
		}
	}
}

// ========== BPF 底层操作 ==========

func openBPF() (int, error) {
	// 尝试 /dev/bpf0 到 /dev/bpf99
	for i := 0; i < 100; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		if err == unix.EBUSY {
			continue
		}
		if err == unix.ENOENT {
			break
		}
	}
	return -1, fmt.Errorf("无法打开 /dev/bpf* (需要 root/sudo)")
}

func defaultInterface() (string, error) {
	// 方法 1: 通过默认路由确定出站接口（最可靠）
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		// 根据本地 IP 反查接口名
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && ip.Equal(localAddr.IP) {
					return iface.Name, nil
				}
			}
		}
	}

	// 方法 2: 按优先级尝试常见的真实接口名
	for _, name := range []string{"en0", "en1", "eth0", "eth1", "wlan0"} {
		iface, err := net.InterfaceByName(name)
		if err == nil && iface.Flags&net.FlagUp != 0 {
			return name, nil
		}
	}

	// 方法 3: 回退到第一个非虚拟的活跃接口
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// 跳过已知的虚拟接口前缀
		name := iface.Name
		skip := false
		for _, prefix := range []string{"utun", "awdl", "llw", "bridge", "gif", "stf", "ap"} {
			if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("未找到活跃网络接口")
}

// BIOCSETIF ioctl 参数
type ifreq struct {
	Name [16]byte
	_    [16]byte // padding
}

func bindBPF(fd int, ifName string) error {
	var req ifreq
	copy(req.Name[:], ifName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}

func setImmediate(fd int) error {
	enable := 1
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCIMMEDIATE), uintptr(unsafe.Pointer(&enable)))
	if errno != 0 {
		return errno
	}
	return nil
}

func getBufLen(fd int) (int, error) {
	var bufLen int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCGBLEN), uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		return 0, errno
	}
	return int(bufLen), nil
}

// installSYNFilter 安装内核级 BPF 过滤器，只捕获 TCP SYN 包（不含 SYN-ACK）。
//
// 等价 tcpdump 表达式: "tcp[tcpflags] == tcp-syn"
// 即 TCP flags 字节 == 0x02 (SYN=1, ACK=0)
//
// BPF 指令 (针对以太网帧):
//   ldh [12]         ; 加载 EtherType
//   jeq #0x0800 L1   ; IPv4?
//   jeq #0x86dd L2   ; IPv6?
//   ret #0           ; 其他丢弃
// L1: (IPv4)
//   ldb [23]         ; IP protocol
//   jeq #6 L3        ; TCP?
//   ret #0
// L3:
//   ldx 4*([14]&0xf) ; IP header length
//   ldb [x+27]       ; TCP flags (14 + IHL + 13)
//   jeq #0x02 ACCEPT ; SYN-only?
//   ret #0
// L2: (IPv6)
//   ldb [20]         ; Next header
//   jeq #6 L4        ; TCP?
//   ret #0
// L4:
//   ldb [67]         ; TCP flags (14+40+13)
//   jeq #0x02 ACCEPT
//   ret #0
// ACCEPT:
//   ret #65535
func installSYNFilter(fd int) error {
	type bpfInsn struct {
		code uint16
		jt   uint8
		jf   uint8
		k    uint32
	}

	// BPF 过滤器：只捕获 TCP SYN 包（flags == 0x02，即 SYN=1 ACK=0）
	// 等价 tcpdump: "tcp[tcpflags] == tcp-syn"
	// 同时处理 IPv4 和 IPv6
	// 14 条指令，无死代码。ACCEPT=12, REJECT=13。
	filter := []bpfInsn{
		{0x28, 0, 0, 12},       //  0: ldh [12] (EtherType)
		{0x15, 0, 5, 0x0800},   //  1: jeq IPv4 → 2, else → 7
		{0x30, 0, 0, 23},       //  2: ldb [23] (IPv4 proto)
		{0x15, 0, 9, 6},        //  3: jeq TCP → 4, else → 13(reject)
		{0xb1, 0, 0, 14},       //  4: ldx 4*([14]&0xf) (IHL)
		{0x50, 0, 0, 27},       //  5: ldb [x+27] (TCP flags)
		{0x15, 5, 6, 0x02},     //  6: jeq SYN → 12(accept), else → 13(reject)
		{0x15, 0, 5, 0x86dd},   //  7: jeq IPv6 → 8, else → 13(reject)
		{0x30, 0, 0, 20},       //  8: ldb [20] (next header)
		{0x15, 0, 3, 6},        //  9: jeq TCP → 10, else → 13(reject)
		{0x30, 0, 0, 67},       // 10: ldb [67] (TCP flags)
		{0x15, 0, 1, 0x02},     // 11: jeq SYN → 12(accept), else → 13(reject)
		{0x06, 0, 0, 0xFFFF},   // 12: ACCEPT
		{0x06, 0, 0, 0},        // 13: REJECT
	}

	prog := struct {
		Len    uint32
		Insns  uintptr
	}{
		Len:   uint32(len(filter)),
		Insns: uintptr(unsafe.Pointer(&filter[0])),
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.BIOCSETF), uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return errno
	}
	return nil
}

// NfConntrackAvailable 在 macOS 上不可用
func NfConntrackAvailable() bool {
	return false
}

// ReadNfConntrackConns 在 macOS 上不可用
func ReadNfConntrackConns() ([]model.ConnectionInfo, error) {
	return nil, nil
}

// ConntrackAvailable 在 macOS 上检查 BPF 是否可用（即是否有 root 权限）
func ConntrackAvailable() bool {
	fd, err := openBPF()
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
