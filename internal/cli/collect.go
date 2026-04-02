package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newCollectCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Run full forensic collection",
		Long:  "Execute all collection phases: selfcheck, preflight, processes, network, persistence, integrity, scoring.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			// --timeline implies both retained and triggerable
			if cfg.WithTimeline {
				cfg.WithRetained = true
				cfg.WithTriggerable = true
			}

			application, err := app.New(cfg)
			if err != nil {
				return err
			}

			// Route to three-state analysis if any extended flags are set
			if cfg.WithRetained || cfg.WithTriggerable {
				return application.RunAnalysis(ctx)
			}
			return application.RunFull(ctx)
		},
	}

	cmd.Flags().BoolVar(&cfg.HashProcesses, "hash-processes", false, "Compute SHA256 of process executables")
	cmd.Flags().BoolVar(&cfg.CollectEnv, "collect-env", false, "Include process environment variables")
	cmd.Flags().BoolVar(&cfg.WithRetained, "with-retained", false, "Include retained (historical) state analysis")
	cmd.Flags().BoolVar(&cfg.WithTriggerable, "with-triggerable", false, "Include triggerable (future execution) analysis")
	cmd.Flags().BoolVar(&cfg.WithTimeline, "timeline", false, "Generate unified timeline (implies --with-retained --with-triggerable)")
	cmd.Flags().DurationVar(&cfg.RetainedWindow, "retained-window", 72*time.Hour, "Time window for retained state analysis")

	return cmd
}
