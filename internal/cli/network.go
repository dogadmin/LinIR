package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newNetworkCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "network",
		Short: "Collect and analyze network connections",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunSingle(ctx, "network")
		},
	}
}
