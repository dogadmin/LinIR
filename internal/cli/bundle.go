package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newBundleCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "bundle",
		Short: "Export results as triage bundle (tar.gz)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			cfg.BundleOutput = true
			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunFull(ctx)
		},
	}
}
