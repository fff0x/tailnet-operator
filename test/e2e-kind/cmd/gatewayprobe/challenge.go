package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	proof "tsunaro.io/tailnet-operator/test/internal/gatewayprobe"
)

const requestMarker = "GWPROBE1"
const replyMarker = "GWREPLY1"
const challengeSize = 32
const requestSize = len(requestMarker) + challengeSize
const replySize = len(replyMarker) + challengeSize + 4

func newChallenge() ([]byte, error) {
	b := make([]byte, challengeSize)
	if _, err := rand.Read(b); err != nil {
		return nil, errRejected
	}
	return b, nil
}

func validSource(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && ip != netip.MustParseAddr("255.255.255.255")
}

func parseReply(data, challenge []byte) (string, error) {
	if len(challenge) != challengeSize || len(data) != replySize || string(data[:len(replyMarker)]) != replyMarker ||
		!bytes.Equal(data[len(replyMarker):len(replyMarker)+challengeSize], challenge) {
		return "", errRejected
	}
	ip := netip.AddrFrom4([4]byte(data[replySize-4:]))
	if !validSource(ip) {
		return "", errRejected
	}
	return ip.String(), nil
}

// The response source is exclusively the accepted socket's address; the wire
// request has no address field. Different markers reject an echo/reflection.
func serveChallenge(c net.Conn) {
	defer c.Close()
	if c.SetDeadline(time.Now().Add(probeTimeout)) != nil {
		return
	}
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	ip := remote.AddrPort().Addr().Unmap()
	if !validSource(ip) {
		return
	}
	request, err := io.ReadAll(io.LimitReader(c, int64(requestSize+1)))
	if err != nil || len(request) != requestSize || string(request[:len(requestMarker)]) != requestMarker {
		return
	}
	reply := append([]byte(replyMarker), request[len(requestMarker):]...)
	address := ip.As4()
	reply = append(reply, address[:]...)
	_ = writeFull(c, reply)
}

func writeFull(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil || n <= 0 {
			return errRejected
		}
		b = b[n:]
	}
	return nil
}

// Fixed-size frames, no multiplexing or reusable connections. Waiting for EOF
// makes an oversized response fail rather than accepting a valid prefix.
func exchangeChallenge(c net.Conn, challenge []byte) (string, string) {
	if writeFull(c, append([]byte(requestMarker), challenge...)) != nil {
		return "", proof.ErrorExchange
	}
	// Native TCP and tsnet's gonet TCP connections both support half-close.
	// The target accepts exactly one frame followed by EOF, never a valid prefix.
	half, ok := c.(interface{ CloseWrite() error })
	if !ok || half.CloseWrite() != nil {
		return "", proof.ErrorExchange
	}
	reply, err := io.ReadAll(io.LimitReader(c, int64(replySize+1)))
	if err != nil {
		return "", proof.ErrorExchange
	}
	source, err := parseReply(reply, challenge)
	if err != nil {
		return "", proof.ErrorReply
	}
	return source, ""
}

// At most 16 accepted backends live at once, each with a five-second deadline.
// Cancellation closes the listener and all active connections before returning.
func serveTarget(ctx context.Context, listener net.Listener) error {
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	var wg sync.WaitGroup
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for c := range active {
			_ = c.Close()
		}
	})
	defer stop()
	defer func() {
		_ = listener.Close()
		mu.Lock()
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	for {
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errRejected
		}
		mu.Lock()
		if ctx.Err() != nil || len(active) >= 16 {
			mu.Unlock()
			_ = c.Close()
			continue
		}
		active[c] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveChallenge(c)
			mu.Lock()
			delete(active, c)
			mu.Unlock()
		}()
	}
}
