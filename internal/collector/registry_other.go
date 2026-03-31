//go:build !linux && !darwin

package collector

import (
	"fmt"
	"runtime"
)

// NewPlatformCollectors returns an error on unsupported platforms.
func NewPlatformCollectors() (*PlatformCollectors, error) {
	return nil, fmt.Errorf("linir: unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}
