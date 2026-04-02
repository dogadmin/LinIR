package triggerable

import (
	"context"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// Collector enumerates future execution paths that would activate without
// further attacker interaction.
type Collector interface {
	// CollectAutostarts finds services/daemons/agents that will run at boot
	// or login without explicit human action.
	CollectAutostarts(ctx context.Context) ([]model.TriggerableEntry, error)

	// CollectScheduled finds cron, timers, at jobs, and scheduled launch items.
	CollectScheduled(ctx context.Context) ([]model.TriggerableEntry, error)

	// CollectKeepalive finds restart-on-failure services, KeepAlive daemons,
	// and SSH forced commands that guarantee re-execution.
	CollectKeepalive(ctx context.Context) ([]model.TriggerableEntry, error)
}

// Collect runs all triggerable state collection phases and assembles the result.
// Non-fatal errors are recorded and returned alongside the state.
func Collect(ctx context.Context, c Collector) (*model.TriggerableState, []model.CollectionError) {
	state := &model.TriggerableState{
		CollectedAt: time.Now(),
		Confidence:  "high",
	}
	var errs []model.CollectionError

	autostarts, err := c.CollectAutostarts(ctx)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "triggerable.autostarts", Message: err.Error()})
	}
	state.Autostarts = autostarts

	scheduled, err := c.CollectScheduled(ctx)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "triggerable.scheduled", Message: err.Error()})
	}
	state.Scheduled = scheduled

	keepalive, err := c.CollectKeepalive(ctx)
	if err != nil {
		errs = append(errs, model.CollectionError{Phase: "triggerable.keepalive", Message: err.Error()})
	}
	state.Keepalive = keepalive

	if len(errs) > 2 {
		state.Confidence = "low"
	} else if len(errs) > 0 {
		state.Confidence = "medium"
	}

	return state, errs
}
