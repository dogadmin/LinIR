//go:build darwin

package retained

import (
	"context"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// NewPlatformCollector returns the macOS retained state collector.
func NewPlatformCollector() (Collector, error) {
	return &darwinRetainedCollector{}, nil
}

type darwinRetainedCollector struct{}

func (c *darwinRetainedCollector) CollectFileTimeline(ctx context.Context, window time.Duration) ([]model.RetainedFileEntry, error) {
	return scanKeyDirs(ctx, darwinKeyDirs(), window)
}

func (c *darwinRetainedCollector) CollectPersistenceChanges(_ context.Context, current []model.PersistenceItem, window time.Duration) ([]model.PersistenceChange, error) {
	return detectPersistenceChanges(current, window), nil
}

func (c *darwinRetainedCollector) CollectArtifacts(_ context.Context, procs []model.ProcessInfo, persistence []model.PersistenceItem) ([]model.ArtifactFinding, error) {
	// macOS: no /proc/maps, so only cross-platform artifact detection
	return detectArtifacts(procs, persistence), nil
}

func (c *darwinRetainedCollector) CollectAuthHistory(_ context.Context, window time.Duration) ([]model.AuthEvent, error) {
	return collectDarwinAuthHistory(window)
}

func (c *darwinRetainedCollector) CollectLogEvents(_ context.Context, window time.Duration) ([]model.LogEvent, error) {
	return collectDarwinLogEvents(window)
}
