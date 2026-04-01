//go:build !linux && !darwin

package watch

import (
	"context"

	"github.com/dogadmin/LinIR/internal/model"
)

// ConntrackMonitor 在非 Linux 平台上不可用
type ConntrackMonitor struct {
	events chan HitEvent
}

func NewConntrackMonitor(store *IOCStore, iface string) *ConntrackMonitor {
	return &ConntrackMonitor{events: make(chan HitEvent)}
}

func (m *ConntrackMonitor) Events() <-chan HitEvent {
	return m.events
}

func (m *ConntrackMonitor) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func ConntrackAvailable() bool {
	return false
}

func NfConntrackAvailable() bool {
	return false
}

func ReadNfConntrackConns() ([]model.ConnectionInfo, error) {
	return nil, nil
}
