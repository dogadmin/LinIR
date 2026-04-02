//go:build !linux && !darwin

package retained

import (
	"os"
	"time"
)

func getFileCtime(_ os.FileInfo) time.Time {
	return time.Time{}
}
