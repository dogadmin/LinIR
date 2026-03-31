//go:build linux

package collector

import (
	"github.com/dogadmin/LinIR/internal/collector/linux"
)

// NewPlatformCollectors returns Linux-specific collectors that read
// directly from /proc, /sys, and filesystem structures.
func NewPlatformCollectors() (*PlatformCollectors, error) {
	return &PlatformCollectors{
		Host:        linux.NewHostCollector(),
		Process:     linux.NewProcessCollector(),
		Network:     linux.NewNetworkCollector(),
		Persistence: linux.NewPersistenceCollector(),
	}, nil
}
