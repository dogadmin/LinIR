//go:build darwin

package macos

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dogadmin/LinIR/internal/model"
)

// listProcFDs 通过 SYS_PROC_INFO 枚举指定 PID 的所有文件描述符。
// 返回 (fd, type) 列表。只关注 type=SOCKET 的 FD。
//
// 等价于 C: proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, bufsize)
func listProcFDs(pid int) ([]procFdInfo, error) {
	bufSize := 4096 // 初始 buffer，足够 ~500 个 FD
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, bufSize)
		ret, _, errno := unix.Syscall6(
			sysProcInfo,
			procInfoCallPidInfo,
			uintptr(pid),
			procPidListFDs,
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if errno != 0 {
			return nil, errno
		}
		n := int(ret)
		if n <= 0 {
			return nil, nil
		}
		if n >= bufSize {
			// buffer 可能不够，翻倍重试
			bufSize *= 2
			continue
		}

		count := n / procFdInfoSize
		fds := make([]procFdInfo, 0, count)
		for i := 0; i < count; i++ {
			off := i * procFdInfoSize
			fd := procFdInfo{
				FD:     int32(binary.LittleEndian.Uint32(buf[off:])),
				FDType: binary.LittleEndian.Uint32(buf[off+4:]),
			}
			fds = append(fds, fd)
		}
		return fds, nil
	}
	return nil, fmt.Errorf("listProcFDs: buffer 多次扩容仍不够")
}

// getSocketFdInfo 获取指定 PID 指定 FD 的 socket 详细信息。
// 返回原始 buffer 用于偏移解析。
//
// 等价于 C: proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf, sizeof(socket_fdinfo))
func getSocketFdInfo(pid int, fd int32) ([]byte, error) {
	buf := make([]byte, socketFdInfoBufSize)
	ret, _, errno := unix.Syscall6(
		sysProcInfo,
		procInfoCallPidFdInfo,
		uintptr(pid),
		procPidFdSocketInfo,
		uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return nil, errno
	}
	n := int(ret)
	if n < minSocketFdInfoBuf {
		return nil, fmt.Errorf("返回数据过短: %d bytes (需要至少 %d)", n, minSocketFdInfoBuf)
	}
	return buf[:n], nil
}

// parseSocketBuf 从 socket_fdinfo 的原始 buffer 中提取连接信息。
// 使用固定偏移量提取字段，附带校验。
func parseSocketBuf(buf []byte, pid int) (*model.ConnectionInfo, error) {
	if len(buf) < minSocketFdInfoBuf {
		return nil, fmt.Errorf("buffer 过短: %d", len(buf))
	}

	// 尝试 primary 偏移，如果校验失败尝试备选偏移
	// 备选偏移 = primary - 16（对应 vinfo_stat=128 的情况）
	offsets := []int{0, -16}
	var soiType, soiProto, soiFamily int32
	var activeOffset int

	found := false
	for _, delta := range offsets {
		typeOff := offSoiType + delta
		protoOff := offSoiProto + delta
		famOff := offSoiFamily + delta
		if typeOff < 0 || famOff+4 > len(buf) {
			continue
		}
		t := int32(binary.LittleEndian.Uint32(buf[typeOff:]))
		p := int32(binary.LittleEndian.Uint32(buf[protoOff:]))
		f := int32(binary.LittleEndian.Uint32(buf[famOff:]))

		// 校验：family 必须是 AF_INET 或 AF_INET6，proto 必须是 TCP 或 UDP
		if (f == afINET || f == afINET6) && (p == ipprotoTCP || p == ipprotoUDP) {
			// 进一步校验 type 与 proto 一致
			if (p == ipprotoTCP && t == sockStream) || (p == ipprotoUDP && t == sockDgram) {
				soiType = t
				soiProto = p
				soiFamily = f
				activeOffset = delta
				found = true
				break
			}
		}
	}

	if !found {
		return nil, nil // 无法识别的 socket 类型
	}

	// 非 IP 协议跳过
	if soiFamily != afINET && soiFamily != afINET6 {
		return nil, nil
	}
	_ = soiType

	// 应用偏移修正到 proto union 内的字段
	d := activeOffset
	vflagOff := offInsiVflag + d
	if vflagOff < 0 || vflagOff >= len(buf) {
		return nil, fmt.Errorf("vflag 偏移越界")
	}
	vflag := buf[vflagOff]

	localIP, localPort, family, err := extractAddr(buf, offInsiLport+d, offInsiV4La+d, offInsiLaddr6+d, vflag)
	if err != nil {
		return nil, fmt.Errorf("解析本地地址: %w", err)
	}

	remoteIP, remotePort, _, err := extractAddr(buf, offInsiFport+d, offInsiV4Fa+d, offInsiFaddr6+d, vflag)
	if err != nil {
		return nil, fmt.Errorf("解析远端地址: %w", err)
	}

	// 确定协议名称
	var proto string
	switch soiProto {
	case ipprotoTCP:
		proto = "tcp"
	case ipprotoUDP:
		proto = "udp"
	}

	conn := &model.ConnectionInfo{
		Proto:         proto,
		Family:        family,
		LocalAddress:  localIP.String(),
		LocalPort:     localPort,
		RemoteAddress: remoteIP.String(),
		RemotePort:    remotePort,
		PID:           pid,
		Source:        "native_api",
		Confidence:    "high",
	}

	// TCP state
	tcpOff := offTcpState + d
	if proto == "tcp" && tcpOff >= 0 && tcpOff+4 <= len(buf) {
		state := int32(binary.LittleEndian.Uint32(buf[tcpOff:]))
		conn.State = tcpStateName(state)
	} else if proto == "udp" {
		conn.State = "STATELESS"
	}

	return conn, nil
}

// pidConnResult 封装单个 PID 的采集结果和失败计数
type pidConnResult struct {
	conns        []model.ConnectionInfo
	parseFail    int // parseSocketBuf 返回错误的次数
	accessDenied int // listProcFDs 因 SIP/权限返回 EPERM/EACCES 的次数
}

// isAccessDeniedError 检查错误是否为 SIP/权限限制导致的访问拒绝
func isAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	// 直接比较 syscall.Errno
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.EPERM, syscall.EACCES, syscall.ESRCH:
			return true
		}
	}
	return false
}

// collectPidConnections 枚举一个进程的所有网络连接
func collectPidConnections(pid int) pidConnResult {
	result := pidConnResult{}

	fds, err := listProcFDs(pid)
	if err != nil {
		if isAccessDeniedError(err) {
			result.accessDenied = 1
		}
		return result
	}

	for _, fd := range fds {
		if fd.FDType != proxFdTypeSocket {
			continue
		}

		buf, err := getSocketFdInfo(pid, fd.FD)
		if err != nil {
			continue // FD 可能已关闭，跳过
		}

		conn, err := parseSocketBuf(buf, pid)
		if err != nil {
			result.parseFail++
			continue
		}
		if conn != nil {
			result.conns = append(result.conns, *conn)
		}
	}

	return result
}
