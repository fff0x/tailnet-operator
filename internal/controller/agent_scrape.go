package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const maxAgentResponseBytes = 1 << 20

var errAgentScrape = errors.New("agent observation unavailable")

// Agent observations go directly to a literal Pod IP, never through ambient proxies
// or redirects. No idle connection is retained for untrusted unsolicited responses.
var agentScrapeHTTPClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
		ResponseHeaderTimeout:  5 * time.Second,
	},
}

func scrapeJSON(ctx context.Context, ip, path string, out any) error {
	return scrapeAgentJSON(ctx, agentScrapeHTTPClient, ip, path, out)
}

func scrapeAgentJSON(ctx context.Context, c *http.Client, ip, path string, out any) error {
	if net.ParseIP(ip) == nil || (path != "targets" && path != "status") {
		return errAgentScrape
	}
	endpoint := (&url.URL{Scheme: "http", Host: net.JoinHostPort(ip, strconv.Itoa(agentHealthPort)), Path: "/" + path}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errAgentScrape
	}
	resp, err := c.Do(req)
	if err != nil {
		return errAgentScrape
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 || resp.ContentLength > maxAgentResponseBytes {
		return errAgentScrape
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentResponseBytes+1))
	if err != nil || len(body) > maxAgentResponseBytes {
		return errAgentScrape
	}
	if json.Unmarshal(body, out) != nil {
		return errAgentScrape
	}
	return nil
}
