package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogadmin/LinIR/internal/model"
)

// TextWriter writes a human-readable text summary.
type TextWriter struct {
	outputDir string
	quiet     bool
}

// NewTextWriter creates a new TextWriter.
func NewTextWriter(outputDir string, quiet bool) *TextWriter {
	return &TextWriter{outputDir: outputDir, quiet: quiet}
}

func (w *TextWriter) Write(result *model.CollectionResult) error {
	id := result.CollectionID
	if len(id) > 8 {
		id = id[:8]
	}

	hostname := result.Host.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	filename := fmt.Sprintf("linir-%s-%s.txt", hostname, id)
	path := filepath.Join(w.outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating text output %s: %w", path, err)
	}
	defer f.Close()

	if err := w.render(f, result); err != nil {
		return err
	}

	// Also write to stdout unless quiet
	if !w.quiet {
		return w.render(os.Stdout, result)
	}
	return nil
}

func (w *TextWriter) render(out io.Writer, r *model.CollectionResult) error {
	fmt.Fprintf(out, "LinIR Forensic Report\n")
	fmt.Fprintf(out, "%s\n", strings.Repeat("=", 60))
	fmt.Fprintf(out, "Host:           %s\n", r.Host.Hostname)
	fmt.Fprintf(out, "Platform:       %s\n", r.Host.Platform)
	fmt.Fprintf(out, "Kernel:         %s\n", r.Host.KernelVersion)
	fmt.Fprintf(out, "Collection ID:  %s\n", r.CollectionID)
	fmt.Fprintf(out, "Started:        %s\n", r.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(out, "Duration:       %dms\n", r.DurationMS)
	fmt.Fprintf(out, "\n")

	// Self-check summary
	fmt.Fprintf(out, "Self-Check Confidence: %s\n", r.SelfCheck.CollectionConfidence)
	fmt.Fprintf(out, "Host Trust Level:      %s\n", r.Preflight.HostTrustLevel)
	fmt.Fprintf(out, "\n")

	// Score summary
	if r.Score != nil {
		fmt.Fprintf(out, "RISK SCORE: %d (%s)\n", r.Score.Total, strings.ToUpper(r.Score.Severity))
		fmt.Fprintf(out, "%s\n", strings.Repeat("-", 40))
		for _, e := range r.Score.Evidence {
			fmt.Fprintf(out, "  [%s] %s/%s: %s (+%d)\n", e.Severity, e.Domain, e.Rule, e.Description, e.Score)
		}
		fmt.Fprintln(out)
	}

	// Process summary
	if len(r.Processes) > 0 {
		suspicious := 0
		for _, p := range r.Processes {
			if len(p.SuspiciousFlags) > 0 {
				suspicious++
			}
		}
		fmt.Fprintf(out, "Processes: %d total, %d suspicious\n", len(r.Processes), suspicious)
	}

	// Connection summary
	if len(r.Connections) > 0 {
		fmt.Fprintf(out, "Connections: %d total\n", len(r.Connections))
	}

	// Persistence summary
	if len(r.Persistence) > 0 {
		risky := 0
		for _, p := range r.Persistence {
			if len(p.RiskFlags) > 0 {
				risky++
			}
		}
		fmt.Fprintf(out, "Persistence: %d items, %d flagged\n", len(r.Persistence), risky)
	}

	// Integrity summary
	if r.Integrity != nil {
		if r.Integrity.RootkitSuspected {
			fmt.Fprintf(out, "\n*** ROOTKIT SUSPECTED ***\n")
		}
		if len(r.Integrity.VisibilityAnomalies) > 0 {
			fmt.Fprintf(out, "Visibility anomalies: %d\n", len(r.Integrity.VisibilityAnomalies))
		}
	}

	// YARA summary
	if len(r.YaraHits) > 0 {
		fmt.Fprintf(out, "YARA hits: %d\n", len(r.YaraHits))
	}

	// Errors
	if len(r.Errors) > 0 {
		fmt.Fprintf(out, "\nCollection Errors (%d):\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(out, "  [%s] %s\n", e.Phase, e.Message)
		}
	}

	fmt.Fprintln(out)
	return nil
}
