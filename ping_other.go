//go:build !windows

package main

import (
	"context"
	"time"
)

func pingHost(_ context.Context, _ string, _ time.Duration) (int64, bool) {
	return -1, false
}
