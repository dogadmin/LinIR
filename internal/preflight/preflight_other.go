//go:build !linux && !darwin

package preflight

import (
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
)

func platformPreflight(result *model.PreflightResult, cfg *config.Config) {
	result.Notes = append(result.Notes, "platform-specific preflight checks not available")
}
