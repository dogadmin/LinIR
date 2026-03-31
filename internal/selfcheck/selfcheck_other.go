//go:build !linux && !darwin

package selfcheck

import "github.com/dogadmin/LinIR/internal/model"

func platformSelfCheck(result *model.SelfCheckResult) {
	result.SelfEnvAnomaly = append(result.SelfEnvAnomaly, "platform-specific self checks not available")
}
