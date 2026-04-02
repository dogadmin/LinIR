//go:build !linux && !darwin

package retained

import (
	"os"

	"github.com/dogadmin/LinIR/internal/model"
)

// fillStatFields is a no-op on unsupported platforms.
func fillStatFields(entry *model.RetainedFileEntry, info os.FileInfo) {
	// UID/GID/ctime not available
}
