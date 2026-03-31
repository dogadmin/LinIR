package report

import (
	"github.com/dogadmin/LinIR/internal/bundle"
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/output"
)

// Generate writes all configured output formats for the given result.
func Generate(cfg *config.Config, result *model.CollectionResult) error {
	writers := output.ForConfig(cfg)
	for _, w := range writers {
		if err := w.Write(result); err != nil {
			return err
		}
	}
	if cfg.BundleOutput {
		return bundle.Create(cfg.OutputDir, result)
	}
	return nil
}
