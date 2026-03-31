package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newProcessCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Collect and analyze running processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunSingle(ctx, "process")
		},
	}

	cmd.Flags().BoolVar(&cfg.HashProcesses, "hash-processes", false, "Compute SHA256 of process executables")
	cmd.Flags().BoolVar(&cfg.CollectEnv, "collect-env", false, "Include process environment variables")

	return cmd
}
