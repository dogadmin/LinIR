//go:build linux

package triggerable

import (
	"context"

	"github.com/dogadmin/LinIR/internal/model"
)

// NewPlatformCollector returns the Linux triggerable state collector.
func NewPlatformCollector() (Collector, error) {
	return &linuxTriggerableCollector{}, nil
}

type linuxTriggerableCollector struct{}

func (c *linuxTriggerableCollector) CollectAutostarts(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectLinuxAutostarts()
}

func (c *linuxTriggerableCollector) CollectScheduled(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectLinuxScheduled()
}

func (c *linuxTriggerableCollector) CollectKeepalive(ctx context.Context) ([]model.TriggerableEntry, error) {
	return collectLinuxKeepalive()
}
