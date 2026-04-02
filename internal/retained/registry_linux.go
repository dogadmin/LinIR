//go:build linux

package retained

import (
	"context"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// NewPlatformCollector returns the Linux retained state collector.
func NewPlatformCollector() (Collector, error) {
	return &linuxRetainedCollector{}, nil
}

type linuxRetainedCollector struct{}

func (c *linuxRetainedCollector) CollectFileTimeline(ctx context.Context, window time.Duration) ([]model.RetainedFileEntry, error) {
	return scanKeyDirs(ctx, linuxKeyDirs(), window)
}

func (c *linuxRetainedCollector) CollectPersistenceChanges(_ context.Context, current []model.PersistenceItem, window time.Duration) ([]model.PersistenceChange, error) {
	return detectPersistenceChanges(current, window), nil
}

func (c *linuxRetainedCollector) CollectArtifacts(_ context.Context, procs []model.ProcessInfo, persistence []model.PersistenceItem) ([]model.ArtifactFinding, error) {
	findings := detectArtifacts(procs, persistence)
	// Linux-specific: check /proc/<pid>/maps for missing mapped files
	findings = append(findings, detectMapsArtifacts(procs)...)
	return findings, nil
}

func (c *linuxRetainedCollector) CollectAuthHistory(_ context.Context, window time.Duration) ([]model.AuthEvent, error) {
	return collectLinuxAuthHistory(window)
}

func (c *linuxRetainedCollector) CollectLogEvents(_ context.Context, window time.Duration) ([]model.LogEvent, error) {
	return collectLinuxLogEvents(window)
}
