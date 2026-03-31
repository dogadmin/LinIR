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
