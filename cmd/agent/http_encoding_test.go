package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPProxyPreservesEncodedResponse(t *testing.T) {
	var stored bytes.Buffer
	encoder := gzip.NewWriter(&stored)
	if _, err := encoder.Write(bytes.Repeat([]byte("synthetic stored object\n"), 128)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	payload := stored.Bytes()
	const etag = `"stored-object-etag"`

	for _, backendTLS := range []bool{false, true} {
		for _, h2 := range []bool{false, true} {
			for _, accept := range []string{"", "identity", "gzip"} {
				t.Run(fmt.Sprintf("backendTLS=%v/http2=%v/accept=%q", backendTLS, h2, accept), func(t *testing.T) {
					seen := make(chan string, 1)
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						seen <- r.Header.Get("Accept-Encoding")
						// Stored S3 content encoding is object metadata, not proxy negotiation.
						w.Header().Set("Content-Type", "application/octet-stream")
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
						w.Header().Set("ETag", etag)
						_, _ = w.Write(payload)
					})
					var h *httpIngress
					var cfg target
					if backendTLS {
						cert, ca := backendCertificate(t, time.Now().Add(time.Hour))
						var pair atomic.Pointer[tls.Certificate]
						pair.Store(&cert)
						backend := backendTestServer(t, &pair, handler)
						h, cfg = tlsBackendIngress(t, backend, ca, backendDNS)
					} else {
						h, cfg = localHTTPIngress(t, handler)
					}
					client := localHTTPClient(t, h, cfg, h2)
					// Observe wire bytes like curl without --compressed; do not hide a proxy decode.
					client.Transport.(*http.Transport).DisableCompression = true
					req, err := http.NewRequest(http.MethodGet, "https://"+testDNS+"/test-bucket/object.gz", nil)
					if err != nil {
						t.Fatal(err)
					}
					if accept != "" {
						req.Header.Set("Accept-Encoding", accept)
					}
					res, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer res.Body.Close()
					body, err := io.ReadAll(res.Body)
					if err != nil {
						t.Fatal(err)
					}
					wantProtocol := 1
					if h2 {
						wantProtocol = 2
					}
					if res.StatusCode != http.StatusOK || res.ProtoMajor != wantProtocol {
						t.Fatalf("unexpected response: %d %s", res.StatusCode, res.Proto)
					}
					if got := <-seen; got != accept {
						t.Errorf("Accept-Encoding changed: incoming=%q backend=%q", accept, got)
					}
					if !bytes.Equal(body, payload) {
						t.Errorf("stored bytes changed: sent=%d received=%d", len(payload), len(body))
					}
					if res.Uncompressed || res.ContentLength != int64(len(payload)) {
						t.Errorf("response representation changed: uncompressed=%v length=%d", res.Uncompressed, res.ContentLength)
					}
					for name, want := range map[string]string{
						"Content-Type":     "application/octet-stream",
						"Content-Encoding": "gzip",
						"Content-Length":   strconv.Itoa(len(payload)),
						"ETag":             etag,
					} {
						if got := res.Header.Get(name); got != want {
							t.Errorf("%s changed: got=%q want=%q", name, got, want)
						}
					}
				})
			}
		}
	}
}
