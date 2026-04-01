package collector

import (
	"context"

	"github.com/dogadmin/LinIR/internal/model"
)

// HostCollector gathers system identity information.
type HostCollector interface {
	CollectHostInfo(ctx context.Context) (*model.HostInfo, error)
}

// ProcessCollector enumerates running processes.
type ProcessCollector interface {
	CollectProcesses(ctx context.Context) ([]model.ProcessInfo, error)
}

// NetworkCollector enumerates network connections.
type NetworkCollector interface {
	CollectConnections(ctx context.Context) ([]model.ConnectionInfo, error)
	// ResolveConnectionPID 快速定向解析单个连接的 PID（不做全量扫描）。
	// 用于 conntrack/BPF 事件的即时 PID 解析，比 CollectConnections 快得多。
	ResolveConnectionPID(conn model.ConnectionInfo) (pid int, processName string)
}

// PersistenceCollector enumerates persistence mechanisms.
type PersistenceCollector interface {
	CollectPersistence(ctx context.Context) ([]model.PersistenceItem, error)
}

// PlatformCollectors bundles all collectors for a single platform.
type PlatformCollectors struct {
	Host        HostCollector
	Process     ProcessCollector
	Network     NetworkCollector
	Persistence PersistenceCollector
}
