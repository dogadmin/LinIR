package cli

import (
	"github.com/spf13/cobra"

	"github.com/dogadmin/LinIR/internal/config"
)

// NewRootCmd creates the root cobra command with all subcommands registered.
func NewRootCmd() *cobra.Command {
	cfg := config.DefaultConfig()

	root := &cobra.Command{
		Use:   "linir",
		Short: "LinIR - Linux/macOS Incident Response Forensic Tool",
		Long: `LinIR collects forensic artifacts from Linux and macOS systems
without relying on target machine commands. It reads /proc, /sys, and
native APIs directly to produce structured evidence for triage.

Trust nothing on the target host. Verify everything through direct parsing
and cross-source validation.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&cfg.OutputDir, "output-dir", "o", cfg.OutputDir, "Output directory")
	pf.StringVar(&cfg.OutputFormat, "format", cfg.OutputFormat, "Output format: json, text, csv, both, all")
	pf.BoolVar(&cfg.BundleOutput, "bundle", cfg.BundleOutput, "Create triage bundle (tar.gz)")
	pf.BoolVar(&cfg.Force, "force", cfg.Force, "Proceed despite preflight failures")
	pf.BoolVarP(&cfg.Verbose, "verbose", "v", cfg.Verbose, "Verbose output")
	pf.BoolVarP(&cfg.Quiet, "quiet", "q", cfg.Quiet, "Suppress non-error output")
	pf.IntVar(&cfg.Timeout, "timeout", cfg.Timeout, "Global timeout in seconds")

	root.AddCommand(
		newCollectCmd(cfg),
		newPreflightCmd(cfg),
		newProcessCmd(cfg),
		newNetworkCmd(cfg),
		newPersistenceCmd(cfg),
		newIntegrityCmd(cfg),
		newYaraCmd(cfg),
		newBundleCmd(cfg),
		newGuiCmd(cfg),
	)

	return root
}
