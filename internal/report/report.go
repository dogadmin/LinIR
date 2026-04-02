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

// GenerateAnalysis writes all configured output formats for a three-state analysis result.
func GenerateAnalysis(cfg *config.Config, result *model.AnalysisResult) error {
	writers := output.AnalysisWritersForConfig(cfg)
	for _, w := range writers {
		if err := w.WriteAnalysis(result); err != nil {
			return err
		}
	}
	if cfg.BundleOutput {
		return bundle.CreateAnalysis(cfg.OutputDir, result)
	}
	return nil
}
