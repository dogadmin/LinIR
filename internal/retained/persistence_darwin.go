//go:build darwin

package retained

import (
	"os"
	"syscall"
	"time"
)

func getFileCtime(info os.FileInfo) time.Time {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(stat.Ctimespec.Sec, stat.Ctimespec.Nsec)
}
