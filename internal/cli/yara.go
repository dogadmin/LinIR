package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/app"
	"github.com/dogadmin/LinIR/internal/config"
)

func newYaraCmd(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "yara",
		Short: "Run YARA scan against specified targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.Timeout)*time.Second)
			defer cancel()

			application, err := app.New(cfg)
			if err != nil {
				return err
			}
			return application.RunYara(ctx)
		},
	}

	cmd.Flags().StringVar(&cfg.YaraRules, "rules", "", "Path to YARA rules file or directory")
	cmd.Flags().StringVar(&cfg.YaraTarget, "target", "", "Target path to scan")
	cmd.Flags().BoolVar(&cfg.YaraProcLinked, "proc-linked", false, "Scan files linked to running processes")

	return cmd
}
