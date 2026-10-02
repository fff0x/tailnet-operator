package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// serveHTTPWithTimeout bounds one HTTP exchange from handler entry through response completion,
// including uploads. It does not buffer bodies or impose a connection-wide server WriteTimeout.
// Successful protocol upgrades finish the HTTP exchange; their tunnels retain normal lifecycle
// cancellation, but no maximum lifetime. SSE remains an HTTP response and is subject to the timer.
// A write deadline also covers informational headers and net/http's buffered final flush AFTER
// handler return. The next exchange resets it; HTTP/2 applies it to the stream, not its connection.
func serveHTTPWithTimeout(w http.ResponseWriter, r *http.Request, handler http.Handler, timeout time.Duration) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	if timeout == 0 {
		handler.ServeHTTP(w, r)
		return
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	tw := &timedResponseWriter{ResponseWriter: w, deadline: time.Now().Add(timeout)}
	if r.ProtoMajor == 1 {
		// Expect: 100-continue may write from net/http's body reader without calling our
		// ResponseWriter. HTTP/2 must stay lazy so an uncommitted timeout can send 504.
		_ = rc.SetWriteDeadline(tw.deadline)
	}
	done := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		defer close(done)
		tw.mu.Lock()
		if tw.finished || tw.upgraded {
			tw.mu.Unlock()
			return
		}
		tw.expired = true
		started, pending := tw.started, tw.pendingUpgrade
		tw.mu.Unlock()
		cancel(context.DeadlineExceeded)
		if pending != nil {
			pending.Close()
			return
		}
		// Transport cancellation alone cannot unblock a slow downstream upload or writer.
		// ResponseController uses per-stream deadlines on HTTP/2, not the shared connection.
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now())
		if started {
			_ = rc.SetWriteDeadline(time.Now())
		}
	})
	finish := sync.OnceFunc(func() {
		tw.mu.Lock()
		tw.finished = true
		tw.mu.Unlock()
		if !timer.Stop() {
			<-done
		}
		tw.mu.Lock()
		expired, upgraded := tw.expired, tw.upgraded
		tw.mu.Unlock()
		if expired && !upgraded {
			_ = rc.SetReadDeadline(time.Time{})
		}
	})
	defer finish() // also joins timeout work when ReverseProxy aborts a committed response
	handler.ServeHTTP(tw, r.WithContext(ctx))
	// Even an empty successful handler causes net/http to write an implicit 200 on return.
	// Establish its write budget before the server performs that buffered final flush.
	tw.WriteHeader(http.StatusOK)
	finish()
	tw.mu.Lock()
	expired, committed, upgraded, failed, hijacked := tw.expired, tw.committed, tw.upgraded, tw.writeFailed, tw.hijacked
	tw.mu.Unlock()
	if (expired || failed) && !upgraded {
		if committed || failed || hijacked {
			panic(http.ErrAbortHandler)
		}
		// Do not retain upstream framing, cookies or cache headers on a generated failure.
		for name := range w.Header() {
			w.Header().Del(name)
		}
		// The original budget has expired. Bound delivery of the small generated 504 too;
		// a client that never reads must not retain a server worker after handler return.
		_ = rc.SetWriteDeadline(time.Now().Add(time.Second))
		if r.ProtoMajor == 1 {
			// Expiring a background HTTP/1 read cancels the connection context permanently.
			// Clearing its deadline does not make that connection safe to reuse.
			w.Header().Set("Connection", "close")
		}
		http.Error(w, "backend request timed out", http.StatusGatewayTimeout)
	}
}

type timedResponseWriter struct {
	http.ResponseWriter
	mu             sync.Mutex
	deadline       time.Time
	started        bool
	committed      bool
	expired        bool
	upgraded       bool
	finished       bool
	writeFailed    bool
	hijacked       bool
	pendingUpgrade net.Conn
}

func (w *timedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *timedResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	if w.expired || w.committed || w.hijacked {
		w.mu.Unlock()
		return
	}
	if code >= 200 {
		w.committed = true
	}
	w.startWriteLocked()
	w.mu.Unlock()
	w.ResponseWriter.WriteHeader(code)
}

func (w *timedResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	if w.expired {
		w.mu.Unlock()
		return 0, context.DeadlineExceeded
	}
	w.committed = true
	w.startWriteLocked()
	w.mu.Unlock()
	n, err := w.ResponseWriter.Write(p)
	w.recordWriteError(err)
	return n, err
}

func (w *timedResponseWriter) FlushError() error {
	w.mu.Lock()
	if w.expired {
		w.mu.Unlock()
		return context.DeadlineExceeded
	}
	w.committed = true
	w.startWriteLocked()
	w.mu.Unlock()
	err := http.NewResponseController(w.ResponseWriter).Flush()
	w.recordWriteError(err)
	return err
}

func (w *timedResponseWriter) Flush() { _ = w.FlushError() }

func (w *timedResponseWriter) startWriteLocked() {
	if !w.started {
		w.started = true
		// Do not install this before output starts: HTTP/2 immediately resets an expired
		// stream, preventing a generated 504 when only the upstream header wait timed out.
		_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(w.deadline)
	}
}

func (w *timedResponseWriter) recordWriteError(err error) {
	if err != nil {
		w.mu.Lock()
		w.writeFailed = true
		w.mu.Unlock()
	}
}

func (w *timedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.expired {
		return nil, nil, context.DeadlineExceeded
	}
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.hijacked = true
	w.pendingUpgrade = conn
	// net/http Hijack clears deadlines. Keep the HTTP budget until the COMPLETE 101
	// header block is written, not merely until Hijack or its first partial write.
	if err := conn.SetWriteDeadline(w.deadline); err != nil {
		conn.Close()
		return nil, nil, err
	}
	// The owned net/http server returns a reset writer and preserves unread request bytes
	// in its reader. Refuse an unexpected writer rather than discard buffered output.
	if rw.Writer.Buffered() != 0 {
		conn.Close()
		return nil, nil, http.ErrNotSupported
	}
	wrapped := &upgradeResponseConn{Conn: conn, owner: w}
	rw.Writer.Reset(wrapped)
	return wrapped, rw, nil
}

// upgradeResponseConn observes only the pending HTTP response header terminator. No header
// content is retained, and established tunnel writes receive no HTTP deadline or idle timer.
type upgradeResponseConn struct {
	net.Conn
	mu          sync.Mutex
	owner       *timedResponseWriter
	tail        uint32
	established bool
}

func (c *upgradeResponseConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.Conn.Write(p)
	if c.established || err != nil {
		return n, err
	}
	for _, b := range p[:n] {
		c.tail = c.tail<<8 | uint32(b)
		if c.tail != 0x0d0a0d0a {
			continue
		}
		c.owner.mu.Lock()
		if c.owner.expired {
			c.owner.mu.Unlock()
			c.Conn.Close()
			return n, context.DeadlineExceeded
		}
		err = c.Conn.SetWriteDeadline(time.Time{})
		if err == nil {
			c.established = true
			c.owner.upgraded = true
			c.owner.pendingUpgrade = nil
		}
		c.owner.mu.Unlock()
		if err != nil {
			c.Conn.Close()
		}
		break
	}
	return n, err
}

func (c *upgradeResponseConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return http.ErrNotSupported
}
