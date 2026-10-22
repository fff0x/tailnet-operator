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

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	if net.ParseIP(ip) == nil || (path != "targets" && path != "status" && path != "dns") {
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

// runningAgentIP returns the Pod IP of one running, non-terminating agent selected by labels,
// or "" when none is up. Shared by every controller that scrapes an agent.
func runningAgentIP(ctx context.Context, c client.Client, ns string, labels map[string]string) string {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return ""
	}
	for _, p := range pods.Items {
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
			return p.Status.PodIP
		}
	}
	return ""
}
