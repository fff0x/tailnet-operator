//go:build e2e

package e2e

import (
	"bytes"
	"sync"
)

// logCapture is a private, thread-safe sink. Snapshots are copies; raw logs are never printed,
// including on assertion failure. A size cap prevents runaway reconcile logs exhausting memory;
// overflow invalidates the redaction verdict instead of silently discarding evidence.
type logCapture struct {
	mu       sync.Mutex
	data     bytes.Buffer
	overflow bool
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	const maxCapture = 16 << 20
	if c.data.Len()+len(p) > maxCapture {
		c.overflow = true
		return len(p), nil
	}
	return c.data.Write(p)
}

func (c *logCapture) snapshot() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.String(), c.overflow
}
