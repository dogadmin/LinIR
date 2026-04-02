//go:build linux

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
	return time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
}
