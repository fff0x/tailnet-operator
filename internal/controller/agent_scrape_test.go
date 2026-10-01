package controller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type agentRoundTripper func(*http.Request) (*http.Response, error)

func (f agentRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type agentErrorReader struct{}

func (agentErrorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE read failure") }

type agentTrackedBody struct {
	io.Reader
	closed bool
	read   int
}

func (b *agentTrackedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}
func (b *agentTrackedBody) Close() error { b.closed = true; return nil }

func TestAgentScrapeBoundsAndRedaction(t *testing.T) {
	const valid = `{"ok":true}`
	for _, tc := range []struct {
		name   string
		reader io.Reader
		status int
		length int64
		wantOK bool
	}{
		{"valid", strings.NewReader(valid), 200, int64(len(valid)), true},
		{"exact-limit", strings.NewReader(valid + strings.Repeat(" ", maxAgentResponseBytes-len(valid))), 200, -1, true},
		{"oversize", strings.NewReader(valid + strings.Repeat(" ", maxAgentResponseBytes)), 200, -1, false},
		{"declared-oversize", strings.NewReader("PRIVATE body"), 200, maxAgentResponseBytes + 1, false},
		{"read-error-after-json", io.MultiReader(strings.NewReader(valid), agentErrorReader{}), 200, -1, false},
		{"invalid", strings.NewReader(`{"PRIVATE malformed`), 200, -1, false},
		{"multiple-documents", strings.NewReader(valid + valid), 200, -1, false},
		{"error-status", strings.NewReader("PRIVATE body"), 500, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &agentTrackedBody{Reader: tc.reader}
			c := &http.Client{Transport: agentRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "[2001:db8::1]:9080" || req.URL.Path != "/targets" {
					t.Fatal("invalid IPv6 Pod endpoint")
				}
				return &http.Response{StatusCode: tc.status, Status: "PRIVATE status", ContentLength: tc.length, Body: body}, nil
			})}
			var out map[string]bool
			err := scrapeAgentJSON(context.Background(), c, "2001:db8::1", "targets", &out)
			if tc.wantOK {
				if err != nil || !out["ok"] {
					t.Fatal("valid observation rejected")
				}
			} else if err != errAgentScrape || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid observation was accepted or leaked diagnostics")
			}
			if !body.closed || body.read > maxAgentResponseBytes+1 {
				t.Fatal("response exceeded its read budget or was not closed")
			}
			if (tc.status != 200 || tc.length > maxAgentResponseBytes) && body.read != 0 {
				t.Fatal("rejected response body was unnecessarily consumed")
			}
		})
	}
}

func TestAgentScrapeRejectsRedirectsAndInvalidEndpoints(t *testing.T) {
	calls := 0
	c := &http.Client{CheckRedirect: agentScrapeHTTPClient.CheckRedirect, Transport: agentRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"http://192.0.2.99/PRIVATE"}}, Body: io.NopCloser(strings.NewReader("PRIVATE body"))}, nil
	})}
	var out any
	if err := scrapeAgentJSON(context.Background(), c, "192.0.2.1", "status", &out); err != errAgentScrape || calls != 1 {
		t.Fatal("redirect followed or accepted")
	}
	for _, endpoint := range [][2]string{{"host.invalid", "targets"}, {"192.0.2.1", "targets?PRIVATE"}, {"fe80::1%eth0", "targets"}, {"192.0.2.1", "routes"}} {
		if scrapeAgentJSON(context.Background(), c, endpoint[0], endpoint[1], &out) != errAgentScrape || calls != 1 {
			t.Fatal("invalid endpoint issued a request")
		}
	}
	transport := agentScrapeHTTPClient.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || transport.MaxResponseHeaderBytes != 64<<10 {
		t.Fatal("agent client bypassed its transport bounds")
	}
	c.Transport = agentRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("PRIVATE transport failure") })
	if scrapeAgentJSON(context.Background(), c, "192.0.2.1", "targets", &out) != errAgentScrape {
		t.Fatal("transport diagnostic escaped")
	}
}
