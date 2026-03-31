//go:build !linux

package integrity

import (
	"context"

	"github.com/dogadmin/LinIR/internal/model"
)

func platformKernelCheck(ctx context.Context, ir *model.IntegrityResult) {
	// 非 Linux 平台暂无内核级检查
}
