//go:build darwin

package triggerable

import (
	"context"

	"github.com/dogadmin/LinIR/internal/model"
)

// NewPlatformCollector returns the macOS triggerable state collector.
func NewPlatformCollector() (Collector, error) {
	return &darwinTriggerableCollector{}, nil
}

type darwinTriggerableCollector struct{}

func (c *darwinTriggerableCollector) CollectAutostarts(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectDarwinAutostarts()
}

func (c *darwinTriggerableCollector) CollectScheduled(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectDarwinScheduled()
}

func (c *darwinTriggerableCollector) CollectKeepalive(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectDarwinKeepalive()
}
