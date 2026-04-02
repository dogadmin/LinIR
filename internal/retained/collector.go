package retained

import (
	"context"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// Collector gathers historical forensic traces from filesystem metadata,
// logs, and artifact residue.
type Collector interface {
	// CollectFileTimeline scans key directories for files modified within
	// the given time window.
	CollectFileTimeline(ctx context.Context, window time.Duration) ([]model.RetainedFileEntry, error)

	// CollectPersistenceChanges detects recently modified persistence
	// configuration files within the time window.
	CollectPersistenceChanges(ctx context.Context, current []model.PersistenceItem, window time.Duration) ([]model.PersistenceChange, error)

	// CollectArtifacts finds deleted exe residue, maps pointing to missing
	// files, and other forensic artifact traces.
	CollectArtifacts(ctx context.Context, procs []model.ProcessInfo, persistence []model.PersistenceItem) ([]model.ArtifactFinding, error)

	// CollectAuthHistory parses authentication logs within the time window.
	CollectAuthHistory(ctx context.Context, window time.Duration) ([]model.AuthEvent, error)

	// CollectLogEvents extracts time-windowed log entries.
	CollectLogEvents(ctx context.Context, window time.Duration) ([]model.LogEvent, error)
}

// Collect runs all retained state collection phases and assembles the result.
// Non-fatal errors are recorded and returned alongside the state.
func Collect(ctx context.Context, c Collector, window time.Duration, procs []model.ProcessInfo, persist []model.PersistenceItem) (*model.RetainedState, []model.CollectionError) {
	state := &model.RetainedState{
		CollectedAt: time.Now(),
		Window:      window.String(),
		Confidence:  "high",
	}
	var errs []model.CollectionError

	files, err := c.CollectFileTimeline(ctx, window)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "retained.file_timeline", Message: err.Error()})
	}
	state.FileTimeline = files

	changes, err := c.CollectPersistenceChanges(ctx, persist, window)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "retained.persistence_changes", Message: err.Error()})
	}
	state.PersistChanges = changes

	artifacts, err := c.CollectArtifacts(ctx, procs, persist)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "retained.artifacts", Message: err.Error()})
	}
	state.Artifacts = artifacts

	authHistory, err := c.CollectAuthHistory(ctx, window)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "retained.auth_history", Message: err.Error()})
	}
	state.AuthHistory = authHistory

	logEvents, err := c.CollectLogEvents(ctx, window)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "retained.log_events", Message: err.Error()})
	}
	state.LogEvents = logEvents

	if len(errs) > 3 {
		state.Confidence = "low"
	} else if len(errs) > 0 {
		state.Confidence = "medium"
	}

	return state, errs
}
