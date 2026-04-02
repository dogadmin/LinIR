//go:build linux

package retained

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dogadmin/LinIR/internal/model"
)

// linuxKeyDirs returns the key directories to scan on Linux.
func linuxKeyDirs() []keyDir {
	dirs := []keyDir{
		{"/tmp", "/tmp", 1},
		{"/var/tmp", "/var/tmp", 1},
		{"/dev/shm", "/dev/shm", 1},
		{"/etc/systemd/system", "/etc/systemd/system", 1},
		{"/run/systemd/system", "/run/systemd/system", 0},
		{"/etc/cron.d", "/etc/cron.d", 0},
		{"/etc/cron.daily", "/etc/cron.daily", 0},
		{"/etc/cron.hourly", "/etc/cron.hourly", 0},
		{"/var/spool/cron", "/var/spool/cron", 1},
		{"/var/spool/cron/crontabs", "/var/spool/cron/crontabs", 0},
		{"/etc/profile.d", "/etc/profile.d", 0},
		{"/usr/local/bin", "/usr/local/bin", 0},
		{"/usr/local/sbin", "/usr/local/sbin", 0},
		// /etc top-level files only (not recursive)
		{"/etc", "/etc", 0},
	}

	// User homes
	dirs = append(dirs, userHomeDirs()...)

	return dirs
}

func userHomeDirs() []keyDir {
	var dirs []keyDir

	// root
	dirs = append(dirs, keyDir{"/root", "/root", 0})
	if info, err := os.Stat("/root/.ssh"); err == nil && info.IsDir() {
		dirs = append(dirs, keyDir{"/root/.ssh", "/root/.ssh", 0})
	}

	// /home users
	entries, err := os.ReadDir("/home")
	if err != nil {
		return dirs
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		home := filepath.Join("/home", entry.Name())
		dirs = append(dirs, keyDir{home, home, 0})
		sshDir := filepath.Join(home, ".ssh")
		if info, err := os.Stat(sshDir); err == nil && info.IsDir() {
			dirs = append(dirs, keyDir{sshDir, sshDir, 0})
		}
	}

	return dirs
}

// fillStatFields extracts UID, GID, and ctime from Linux syscall.Stat_t.
func fillStatFields(entry *model.RetainedFileEntry, info os.FileInfo) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	entry.UID = int(stat.Uid)
	entry.GID = int(stat.Gid)
	entry.ChangeTime = time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
}
