// Command tailnet-console is the read-only web console. It signs people in with OIDC, takes their
// role from the groups claim and shows the Tailnets, spokes, TailnetIngresses and TailnetSites it
// reads through a watch cache, and the person's access from the operator's console API. It writes
// nothing.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
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
	}
}

func run(ctx context.Context, l logr.Logger) error {
	scheme := runtime.NewScheme()
	if err := tnv1.AddToScheme(scheme); err != nil {
		return err
	}
	c, err := cache.New(ctrl.GetConfigOrDie(), cache.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	for _, obj := range []client.Object{&tnv1.Tailnet{}, &tnv1.TailnetIngress{}, &tnv1.TailnetSite{}, &tnv1.TailnetGrant{}} {
		if _, err := c.GetInformer(ctx, obj); err != nil {
			return err
		}
	}
	srv, err := console.New(configFromEnv(os.Getenv), c, l)
	if err != nil {
		return err
	}
	go func() { _ = c.Start(ctx) }()
	if !c.WaitForCacheSync(ctx) {
		return errors.New("cache did not sync")
	}
	hs := &http.Server{Addr: ":8080", Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	l.Info("serving", "addr", hs.Addr)
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
