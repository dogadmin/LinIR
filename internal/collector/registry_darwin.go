//go:build darwin

package collector

import (
	"github.com/dogadmin/LinIR/internal/collector/macos"
)

// NewPlatformCollectors returns macOS-specific collectors that use
// native APIs (sysctl, libproc) and filesystem structures (plist, LaunchAgents).
func NewPlatformCollectors() (*PlatformCollectors, error) {
	return &PlatformCollectors{
		Host:        macos.NewHostCollector(),
		Process:     macos.NewProcessCollector(),
		Network:     macos.NewNetworkCollector(),
		Persistence: macos.NewPersistenceCollector(),
	}, nil
}
