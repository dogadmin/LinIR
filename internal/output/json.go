package output

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/pkg/jsonutil"
)

// JSONWriter writes the full collection result as pretty-printed JSON.
type JSONWriter struct {
	outputDir string
}

// NewJSONWriter creates a new JSONWriter targeting the given directory.
func NewJSONWriter(outputDir string) *JSONWriter {
	return &JSONWriter{outputDir: outputDir}
}

func (w *JSONWriter) Write(result *model.CollectionResult) error {
	id := result.CollectionID
	if len(id) > 8 {
		id = id[:8]
	}

	hostname := result.Host.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	filename := fmt.Sprintf("linir-%s-%s.json", hostname, id)
	path := filepath.Join(w.outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating JSON output %s: %w", path, err)
	}
	defer f.Close()

	return jsonutil.WriteJSON(f, result)
}
