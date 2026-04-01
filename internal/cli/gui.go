package cli

import (
	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/config"
	"github.com/dogadmin/LinIR/internal/web"
)

func newGuiCmd(cfg *config.Config) *cobra.Command {
	host := "127.0.0.1"
	port := 18080

	cmd := &cobra.Command{
		Use:   "gui",
		Short: "Launch web-based GUI dashboard",
		Long: `Start a local HTTP server and open the LinIR forensic dashboard
in your default browser.

The GUI provides:
  - One-click collection trigger
  - Real-time risk score and host trust visualization
  - Interactive process, network, persistence tables with search/filter
  - Evidence breakdown and integrity check results
  - JSON export from browser`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := web.NewServer(cfg, host, port)
			return srv.Start()
		},
	}

	cmd.Flags().StringVar(&host, "host", host, "监听地址 (默认 127.0.0.1，使用 0.0.0.0 允许外部访问)")
	cmd.Flags().IntVar(&port, "port", port, "HTTP server port")

	return cmd
}
