package retained

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
	"github.com/dogadmin/LinIR/internal/score"
	"github.com/dogadmin/LinIR/pkg/userutil"
)

// scanKeyDirs walks the given directories and collects files modified within the window.
// This is the shared logic used by both Linux and macOS platform collectors.
func scanKeyDirs(ctx context.Context, dirs []keyDir, window time.Duration) ([]model.RetainedFileEntry, error) {
	cutoff := time.Now().Add(-window)
	userCache := make(map[int]string)
	var entries []model.RetainedFileEntry

	for _, kd := range dirs {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}

		dirEntries, err := scanOneDir(ctx, kd.path, kd.label, kd.maxDepth, cutoff, userCache)
		if err != nil {
			continue
		}
		entries = append(entries, dirEntries...)
	}
	return entries, nil
}

// keyDir describes a directory to scan for the retained file timeline.
type keyDir struct {
	path     string
	label    string // human-readable label for key_dir field
	maxDepth int    // 0 = only direct children, 1 = one level of subdirs, etc.
}

func scanOneDir(ctx context.Context, root, label string, maxDepth int, cutoff time.Time, userCache map[int]string) ([]model.RetainedFileEntry, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", root)
	}

	var entries []model.RetainedFileEntry
	err = walkDir(ctx, root, label, 0, maxDepth, cutoff, userCache, &entries)
	return entries, err
}

func walkDir(ctx context.Context, dir, label string, depth, maxDepth int, cutoff time.Time, userCache map[int]string, entries *[]model.RetainedFileEntry) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, de := range dirEntries {
		path := filepath.Join(dir, de.Name())

		if de.IsDir() {
			if depth < maxDepth {
				walkDir(ctx, path, label, depth+1, maxDepth, cutoff, userCache, entries)
			}
			continue
		}

		info, err := de.Info()
		if err != nil {
			continue
		}

		modTime := info.ModTime()
		if modTime.Before(cutoff) {
			continue
		}

		entry := model.RetainedFileEntry{
			Path:       path,
			Size:       info.Size(),
			Mode:       info.Mode().String(),
			ModTime:    modTime,
			Executable: info.Mode().Perm()&0111 != 0,
			KeyDir:     label,
			Confidence: "high",
		}

		// UID/GID and ctime via platform-specific stat
		fillStatFields(&entry, info)

		// Owner name
		if entry.UID > 0 {
			entry.Owner = userutil.ResolveUsername(entry.UID, userCache)
		}

		// Risk flags
		flagFileRisks(&entry, info)

		*entries = append(*entries, entry)
	}
	return nil
}

func flagFileRisks(entry *model.RetainedFileEntry, info os.FileInfo) {
	path := entry.Path

	// Executable in suspicious location (tmp dirs)
	if entry.Executable {
		if score.IsInTmpDir(path) {
			entry.RiskFlags = append(entry.RiskFlags, "executable_in_tmp")
		}
	}

	// Hidden executable in non-hidden system directory — more specific than just "hidden file"
	if entry.Executable {
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") && !strings.HasPrefix(filepath.Base(filepath.Dir(path)), ".") {
			entry.RiskFlags = append(entry.RiskFlags, "hidden_executable")
		}
	}

	// World-writable executable — more targeted than flagging all world-writable files
	if entry.Executable && info.Mode().Perm()&0002 != 0 {
		entry.RiskFlags = append(entry.RiskFlags, "world_writable_executable")
	}

	// Setuid/setgid only in unusual directories (not /usr/bin, /usr/sbin, /usr/lib, /bin, /sbin)
	if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		if !isStandardSetuidDir(path) {
			entry.RiskFlags = append(entry.RiskFlags, "setuid_unusual_dir")
		}
	}
}

func isStandardSetuidDir(path string) bool {
	standard := []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/bin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/"}
	for _, prefix := range standard {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
