//go:build !linux && !darwin

package retained

import (
	"fmt"
	"runtime"
)

// NewPlatformCollector returns an error on unsupported platforms.
func NewPlatformCollector() (Collector, error) {
	return nil, fmt.Errorf("retained: unsupported platform %s", runtime.GOOS)
}
