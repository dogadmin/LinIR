package bundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// Create produces a .tar.gz triage bundle containing structured JSON outputs.
func Create(outputDir string, result *model.CollectionResult) error {
	id := result.CollectionID
	if len(id) > 8 {
		id = id[:8]
	}

	hostname := result.Host.Hostname
	if hostname == "" {
		hostname = "unknown"
	}

	bundleName := fmt.Sprintf("linir-bundle-%s-%s.tar.gz", hostname, id)
	bundlePath := filepath.Join(outputDir, bundleName)

	f, err := os.Create(bundlePath)
	if err != nil {
		return fmt.Errorf("creating bundle %s: %w", bundlePath, err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	prefix := fmt.Sprintf("linir-%s-%s", hostname, id)

	// Write each section as a separate JSON file
	sections := map[string]interface{}{
		"host.json":        result.Host,
		"self_check.json":  result.SelfCheck,
		"preflight.json":   result.Preflight,
		"processes.json":   result.Processes,
		"connections.json": result.Connections,
		"persistence.json": result.Persistence,
		"integrity.json":   result.Integrity,
		"yara_hits.json":   result.YaraHits,
		"score.json":       result.Score,
		"errors.json":      result.Errors,
		"full.json":        result,
	}

	for name, data := range sections {
		if data == nil {
			continue
		}
		jsonBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling %s: %w", name, err)
		}
		if err := addBytesToTar(tw, filepath.Join(prefix, name), jsonBytes); err != nil {
			return fmt.Errorf("adding %s to bundle: %w", name, err)
		}
	}

	return nil
}

func addBytesToTar(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addFileToTar(tw *tar.Writer, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.Base(path)
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}
