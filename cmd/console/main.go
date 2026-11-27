// Command tailnet-console is the web console. It signs people in with OIDC, takes their role from
// the groups claim and shows the Tailnets, spokes, TailnetIngresses and TailnetSites it reads
// through a watch cache, and the person's access from the operator's console API. Only with
// CONSOLE_AUDIT_DIR set it writes: admins create, extend and revoke TailnetGrants and decide
// access requests, each change recorded first in the audit log on that directory, and it serves
// metrics on :8081.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
	"tsunaro.io/tailnet-operator/internal/console"
)

func main() {
	ctrl.SetLogger(zap.New())
	l := ctrl.Log.WithName("console")
	if err := run(ctrl.SetupSignalHandler(), l); err != nil {
		l.Error(err, "console exited")
		os.Exit(1)
	}
}

func configFromEnv(getenv func(string) string) console.Config {
	return console.Config{
		URL: getenv("CONSOLE_URL"), Issuer: getenv("OIDC_ISSUER"), ClientID: getenv("OIDC_CLIENT_ID"),
		ClientSecret: getenv("OIDC_CLIENT_SECRET"), Scopes: strings.Fields(strings.ReplaceAll(getenv("OIDC_SCOPES"), ",", " ")),
		AdminGroup: getenv("CONSOLE_ADMIN_GROUP"), UserGroup: getenv("CONSOLE_USER_GROUP"),
		OperatorURL: getenv("CONSOLE_OPERATOR_URL"), TokenFile: getenv("CONSOLE_API_TOKEN_FILE"),
		AuditDir: getenv("CONSOLE_AUDIT_DIR"), AuditAnchor: getenv("CONSOLE_AUDIT_ANCHOR"), Namespace: getenv("POD_NAMESPACE"),
		FourEyes: getenv("CONSOLE_FOUR_EYES") == "true",
	}
}

func run(ctx context.Context, l logr.Logger) error {
	scheme := runtime.NewScheme()
	if err := tnv1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	rc := ctrl.GetConfigOrDie()
	c, err := cache.New(rc, cache.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	for _, obj := range []client.Object{&tnv1.Tailnet{}, &tnv1.TailnetIngress{}, &tnv1.TailnetSite{}, &tnv1.TailnetGrant{}} {
		if _, err := c.GetInformer(ctx, obj); err != nil {
			return err
		}
	}
	cfg := configFromEnv(os.Getenv)
	// The writer reads and writes the API server directly: the role allows one ConfigMap by name,
	// which a cache could not watch, and the grant pages must not show a stale list.
	var writer client.Client
	if cfg.AuditDir != "" {
		if writer, err = client.New(rc, client.Options{Scheme: scheme}); err != nil {
			return err
		}
	}
	srv, err := console.New(cfg, c, writer, l)
	if err != nil {
		return err
	}
	go func() { _ = c.Start(ctx) }()
	if !c.WaitForCacheSync(ctx) {
		return errors.New("cache did not sync")
	}
	srv.CheckAudit(ctx)
	servers := []*http.Server{{Addr: ":8080", Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}}
	if mh := srv.MetricsHandler(); mh != nil {
		go srv.WatchAudit(ctx, 10*time.Minute)
		servers = append(servers, &http.Server{Addr: ":8081", Handler: mh, ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10})
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, hs := range servers {
			_ = hs.Shutdown(shutdown)
		}
	}()
	errs := make(chan error, len(servers))
	for _, hs := range servers {
		l.Info("serving", "addr", hs.Addr)
		go func() { errs <- hs.ListenAndServe() }()
	}
	for range servers {
		if err := <-errs; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}
