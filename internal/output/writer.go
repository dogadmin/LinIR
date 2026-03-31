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
// Supported formats: "json", "text", "csv", "both" (json+text), "all" (json+text+csv)
func ForConfig(cfg *config.Config) []Writer {
	var writers []Writer
	switch cfg.OutputFormat {
	case "json":
		writers = append(writers, NewJSONWriter(cfg.OutputDir))
	case "text":
		writers = append(writers, NewTextWriter(cfg.OutputDir, cfg.Quiet))
	case "csv":
		writers = append(writers, NewCSVWriter(cfg.OutputDir))
	case "all":
		writers = append(writers, NewJSONWriter(cfg.OutputDir))
		writers = append(writers, NewTextWriter(cfg.OutputDir, cfg.Quiet))
		writers = append(writers, NewCSVWriter(cfg.OutputDir))
	default: // "both" = json + text (backward compatible)
		writers = append(writers, NewJSONWriter(cfg.OutputDir))
		writers = append(writers, NewTextWriter(cfg.OutputDir, cfg.Quiet))
	}
	return writers
}
