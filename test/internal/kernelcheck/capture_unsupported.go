//go:build !linux

package kernelcheck

func Capture(string) (Snapshot, error) { return Snapshot{}, ErrSnapshot }
