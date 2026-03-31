//go:build linux

package procfs

import (
	"fmt"
	"strconv"
	"strings"
)

// ProcStat 表示 /proc/[pid]/stat 解析后的关键字段
//
// /proc/[pid]/stat 格式 (man 5 proc):
//   pid (comm) state ppid pgrp session tty_nr tpgid flags
//   minflt cminflt majflt cmajflt utime stime cutime cstime
//   priority nice num_threads itrealvalue starttime vsize rss ...
//
// 从 ')' 之后开始数（0-indexed）:
//   [0]=state [1]=ppid [2]=pgrp [3]=session [4]=tty_nr [5]=tpgid [6]=flags
//   [7]=minflt [8]=cminflt [9]=majflt [10]=cmajflt
//   [11]=utime [12]=stime [13]=cutime [14]=cstime
//   [15]=priority [16]=nice [17]=num_threads [18]=itrealvalue
//   [19]=starttime [20]=vsize [21]=rss
type ProcStat struct {
	PID       int
	Comm      string // 进程名（括号内的部分）
	State     byte   // R=running, S=sleeping, D=disk sleep, Z=zombie, T=stopped
	PPID      int
	PGRP      int
	Session   int
	TTY       int
	TPGID     int
	Flags     uint64
	UTime     uint64 // 用户态 CPU 时间 (clock ticks)
	STime     uint64 // 内核态 CPU 时间 (clock ticks)
	NumThreads int
	StartTime uint64 // 进程启动时间 (clock ticks since boot)
	VSize     uint64 // 虚拟内存大小 (bytes)
	RSS       int64  // 驻留内存页数 (pages)
}

// ReadStat 解析 /proc/[pid]/stat
// 如果进程已退出（ENOENT），返回 nil, nil
func ReadStat(pid int) (*ProcStat, error) {
	path := fmt.Sprintf("%s/%d/stat", ProcRoot, pid)
	content, err := ReadFileString(path)
	if err != nil {
		return nil, err
	}
	if content == "" {
		return nil, nil
	}
	return parseStat(content)
}

func parseStat(content string) (*ProcStat, error) {
	// comm 可以包含空格和括号，所以必须找最后一个 ')' 来定界
	openParen := strings.IndexByte(content, '(')
	closeParen := strings.LastIndexByte(content, ')')
	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return nil, fmt.Errorf("procfs: stat 格式异常: %q", content)
	}

	stat := &ProcStat{}

	// PID: '(' 之前的部分
	pidStr := strings.TrimSpace(content[:openParen])
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("procfs: 解析 pid 失败: %w", err)
	}
	stat.PID = pid

	// comm: '(' 和 ')' 之间
	stat.Comm = content[openParen+1 : closeParen]

	// ')' 之后的所有字段
	rest := strings.TrimSpace(content[closeParen+1:])
	fields := strings.Fields(rest)
	if len(fields) < 22 {
		return nil, fmt.Errorf("procfs: stat 字段不足: %d (需要至少 22)", len(fields))
	}

	stat.State = fields[0][0]
	stat.PPID = atoi(fields[1])
	stat.PGRP = atoi(fields[2])
	stat.Session = atoi(fields[3])
	stat.TTY = atoi(fields[4])
	stat.TPGID = atoi(fields[5])
	stat.Flags = atoui64(fields[6])
	// [7..10] = minflt, cminflt, majflt, cmajflt
	stat.UTime = atoui64(fields[11])
	stat.STime = atoui64(fields[12])
	// [13..14] = cutime, cstime
	// [15..16] = priority, nice
	stat.NumThreads = atoi(fields[17])
	// [18] = itrealvalue (不再使用)
	stat.StartTime = atoui64(fields[19])
	stat.VSize = atoui64(fields[20])
	stat.RSS, _ = strconv.ParseInt(fields[21], 10, 64)

	return stat, nil
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func atoui64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}
