package config

import "time"

// Version is set at build time via -ldflags.
var Version = "0.1.0-dev"

// Config holds all runtime configuration, populated from CLI flags.
type Config struct {
	Version       string
	OutputDir     string
	OutputFormat  string // "json"|"text"|"both"
	BundleOutput  bool
	Force         bool
	Verbose       bool
	Quiet         bool
	Timeout       int
	HashProcesses bool
	CollectEnv    bool
	YaraRules     string
	YaraTarget    string
	YaraProcLinked bool

	// Three-state analysis flags
	WithRetained    bool
	WithTriggerable bool
	WithTimeline    bool
	RetainedWindow  time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Version:        Version,
		OutputDir:      ".",
		OutputFormat:   "both",
		Timeout:        300,
		RetainedWindow: 72 * time.Hour,
	}
}
