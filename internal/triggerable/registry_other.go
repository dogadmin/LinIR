//go:build !linux && !darwin

package triggerable

import (
	"fmt"
	"runtime"
)

// NewPlatformCollector returns an error on unsupported platforms.
func NewPlatformCollector() (Collector, error) {
	return nil, fmt.Errorf("triggerable: unsupported platform %s", runtime.GOOS)
}
