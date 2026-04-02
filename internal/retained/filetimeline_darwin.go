//go:build darwin

package retained

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// darwinKeyDirs returns the key directories to scan on macOS.
func darwinKeyDirs() []keyDir {
	dirs := []keyDir{
		{"/tmp", "/tmp", 1},
		{"/private/tmp", "/private/tmp", 1},
		{"/Library/LaunchDaemons", "/Library/LaunchDaemons", 0},
		{"/Library/LaunchAgents", "/Library/LaunchAgents", 0},
		{"/etc", "/etc", 0},
		{"/usr/local/bin", "/usr/local/bin", 0},
		{"/usr/local/sbin", "/usr/local/sbin", 0},
	}

	// User homes
	userDirs, _ := os.ReadDir("/Users")
	for _, ud := range userDirs {
		if !ud.IsDir() || ud.Name() == "Shared" {
			continue
		}
		home := filepath.Join("/Users", ud.Name())
		dirs = append(dirs, keyDir{home, home, 0})
		sshDir := filepath.Join(home, ".ssh")
		if info, err := os.Stat(sshDir); err == nil && info.IsDir() {
			dirs = append(dirs, keyDir{sshDir, sshDir, 0})
		}
		launchAgents := filepath.Join(home, "Library", "LaunchAgents")
		if info, err := os.Stat(launchAgents); err == nil && info.IsDir() {
			dirs = append(dirs, keyDir{launchAgents, launchAgents, 0})
		}
	}

	// Current user home if not under /Users
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, keyDir{home, home, 0})
		sshDir := filepath.Join(home, ".ssh")
		if info, err := os.Stat(sshDir); err == nil && info.IsDir() {
			dirs = append(dirs, keyDir{sshDir, sshDir, 0})
		}
	}

	return dirs
}

// fillStatFields extracts UID, GID, and ctime from macOS syscall.Stat_t.
func fillStatFields(entry *model.RetainedFileEntry, info os.FileInfo) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	entry.UID = int(stat.Uid)
	entry.GID = int(stat.Gid)
	entry.ChangeTime = time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
}
