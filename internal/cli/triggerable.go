package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newTriggerableCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "triggerable",
		Short: "Enumerate future execution paths",
		Long:  "List autostarts, scheduled tasks, keepalive services, and other mechanisms that will execute without further interaction.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			cfg.WithTriggerable = true
			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunTriggerable(ctx)
		},
	}

	return cmd
}
