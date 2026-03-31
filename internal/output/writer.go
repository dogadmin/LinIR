package output

import (
	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/model"
)

// Writer is the interface for all output formats.
type Writer interface {
	Write(result *model.CollectionResult) error
}

// ForConfig returns the appropriate writers based on configuration.
func ForConfig(cfg *config.Config) []Writer {
	var writers []Writer
	switch cfg.OutputFormat {
	case "json":
		writers = append(writers, NewJSONWriter(cfg.OutputDir))
	case "text":
		writers = append(writers, NewTextWriter(cfg.OutputDir, cfg.Quiet))
	default: // "both"
		writers = append(writers, NewJSONWriter(cfg.OutputDir))
		writers = append(writers, NewTextWriter(cfg.OutputDir, cfg.Quiet))
	}
	return writers
}
