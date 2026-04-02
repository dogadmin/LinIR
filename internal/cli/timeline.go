package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newTimelineCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "timeline",
		Short: "Generate unified forensic timeline",
		Long:  "Run full three-state analysis (runtime + retained + triggerable) and produce a unified timeline.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			cfg.WithRetained = true
			cfg.WithTriggerable = true
			cfg.WithTimeline = true
			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunTimeline(ctx)
		},
	}

	cmd.Flags().DurationVar(&cfg.RetainedWindow, "window", 72*time.Hour, "Lookback window for historical traces")

	return cmd
}
