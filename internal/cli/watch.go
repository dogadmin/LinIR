package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/watch"
)

func newWatchCmd(cfg *config.Config) *cobra.Command {
	wcfg := watch.WatchConfig{
		Interval:     1 * time.Second,
		DedupeWindow: 60 * time.Second,
		TextOutput:   true,
	}

	var durationSec int
	var intervalSec int

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "IOC online monitoring mode",
		Long: `Continuously monitor network connections against an IOC list.
When a connection matches an IOC, LinIR immediately collects process,
binary, persistence, YARA, and integrity context to form a scored,
structured hit event.

IOC file format: one IOC per line (IP or domain), # for comments.
  1.2.3.4
  evil.example.com
  10.0.0.1 c2,apt28

Whitelist file format: one entry per line with type prefix.
  process:sshd
  path:/usr/lib/systemd/
  ioc:8.8.8.8`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if durationSec > 0 {
				wcfg.Duration = time.Duration(durationSec) * time.Second
			}
			if intervalSec > 0 {
				wcfg.Interval = time.Duration(intervalSec) * time.Second
			}
			wcfg.OutputDir = cfg.OutputDir
			wcfg.Verbose = cfg.Verbose
			wcfg.YaraRules = cfg.YaraRules

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			engine, err := watch.NewEngine(wcfg, cfg)
			if err != nil {
				return err
			}
			return engine.Run(ctx)
		},
	}

	f := cmd.Flags()
	f.StringVar(&wcfg.IOCFile, "iocs", "", "IOC list file path (required)")
	f.IntVar(&durationSec, "duration", 0, "Monitoring duration in seconds (0=unlimited)")
	f.IntVar(&intervalSec, "interval", 1, "Polling interval in seconds")
	f.BoolVar(&wcfg.JSONOutput, "json", false, "Output JSON events to file")
	f.BoolVar(&wcfg.TextOutput, "text", true, "Output text events to stdout")
	f.BoolVar(&wcfg.BundleOutput, "bundle", false, "Output per-event bundle directories")
	f.StringVar(&wcfg.WhitelistFile, "whitelist", "", "Whitelist file path")
	f.IntVar(&wcfg.MaxEvents, "max-events", 0, "Max events per minute (0=unlimited)")
	f.StringVar(&cfg.YaraRules, "yara-rules", "", "YARA rules file/directory for hit scanning")
	f.StringVar(&wcfg.Interface, "iface", "", "Network interface for BPF capture (e.g. en0, eth0; empty=auto)")

	cmd.MarkFlagRequired("iocs")

	return cmd
}
