package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newRetainedCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "retained",
		Short: "Collect historical forensic traces",
		Long:  "Analyze file modification timelines, persistence changes, deleted artifacts, and authentication history.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			cfg.WithRetained = true
			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunRetained(ctx)
		},
	}

	cmd.Flags().DurationVar(&cfg.RetainedWindow, "window", 72*time.Hour, "Lookback window for historical traces")

	return cmd
}
