package console

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// The console's metrics carry no person: Tailnet names only (rule 13).
var (
	pendingDesc = prometheus.NewDesc("tailnet_console_access_requests_pending",
		"Access requests waiting for a decision, by Tailnet.", []string{"tailnet"}, nil)
	breaksDesc = prometheus.NewDesc("tailnet_console_audit_chain_breaks",
		"Breaks of the audit log's hash chain found by the last check; a recorded break stays.", nil, nil)
)

type collector struct{ s *Server }

func (c collector) Describe(ch chan<- *prometheus.Desc) { ch <- pendingDesc; ch <- breaksDesc }

func (c collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	counts, err := c.s.pending(ctx)
	if err != nil {
		ch <- prometheus.NewInvalidMetric(pendingDesc, err)
	}
	for tn, n := range counts {
		ch <- prometheus.MustNewConstMetric(pendingDesc, prometheus.GaugeValue, float64(n), tn)
	}
	ch <- prometheus.MustNewConstMetric(breaksDesc, prometheus.GaugeValue, float64(c.s.breaks.Load()))
}

// MetricsHandler serves GET /metrics. Without access management the console has no metrics and
// it returns nil.
func (s *Server) MetricsHandler() http.Handler {
	if s.audit == nil {
		return nil
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector{s})
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	return mux
}
