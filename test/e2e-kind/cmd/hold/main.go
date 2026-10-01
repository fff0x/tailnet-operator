// hold is an explicitly marked, non-root, bounded fixture; no I/O or network.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func validate(args []string, uid int) error {
	if uid != 65532 || len(args) != 1 || args[0] != "--fixture=p1.8-layered-isolation" {
		return errors.New("holder-rejected")
	}
	return nil
}

func wait(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func main() {
	if err := validate(os.Args[1:], os.Getuid()); err != nil {
		fmt.Fprintln(os.Stderr, "holder-rejected")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	wait(ctx, 180*time.Second)
}
