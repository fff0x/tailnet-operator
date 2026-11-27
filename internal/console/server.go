// Package console serves the web console: OIDC sign-in, roles from the groups claim, an overview of
// tailnets, spokes, ingresses and sites read from the Kubernetes API, the signed-in person's access
// from the live policy the operator's console API returns, and, when switched on, TailnetGrants
// managed by admins behind a hash-chained audit log, with access requests that admins approve.
package console

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//go:embed assets
var assets embed.FS

// The only script is the embedded page module; it may fetch the console's own pages.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// pollInterval is how often the overview's module reloads the map and tables.
const pollInterval = 10 * time.Second

// Server is the console's HTTP surface.
type Server struct {
	auth   *authenticator
	reader client.Reader
	dir    *directory
	log    logr.Logger
	pages  map[string]*template.Template
	poll   time.Duration
	// writer and audit are set only with access management.
	writer    client.Client
	audit     *auditLog
	now       func() time.Time
	fourEyes  bool
	retention int          // days before the console deletes what is done; 0 deletes nothing
	decisions sync.Mutex   // one request decision at a time; taken before changes
	changes   sync.Mutex   // an audit entry and its change, or one observation run
	breaks    atomic.Int64 // audit chain breaks found by the last check
}

type page struct {
	Title   string
	Session *session
	Manage  bool // the grant and audit links: access management is on and the session is an admin
	// Requests links the request page with access management; Pending counts the undecided
	// requests for an admin.
	Requests bool
	Pending  int
	Body     any
}

type message struct{ Heading, Text string }

// New creates the server with a fresh session key: a restart signs everybody out.
// writer creates and patches TailnetGrants and the audit anchor; it is used only when
// cfg.AuditDir is set.
func New(cfg Config, reader client.Reader, writer client.Client, log logr.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.AuditDir != "" && writer == nil {
		return nil, errors.New("console access management needs a writing client")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	seal, err := newSealer(key, time.Now)
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, name := range []string{"overview", "access", "message", "grants", "grant_new", "audit", "requests"} {
		files := []string{"assets/layout.html", "assets/" + name + ".html"}
		if name == "overview" {
			files = append(files, "assets/map.html")
		}
		t, err := template.New(name).Funcs(template.FuncMap{"add": func(a, b int) int { return a + b }}).ParseFS(assets, files...)
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	s := &Server{
		auth:   &authenticator{cfg: cfg, seal: seal, now: time.Now, client: &http.Client{Timeout: 10 * time.Second}},
		reader: reader, dir: newDirectory(cfg.OperatorURL, cfg.TokenFile), log: log, pages: pages, poll: pollInterval, now: time.Now,
	}
	if cfg.AuditDir != "" {
		s.writer, s.fourEyes, s.retention = writer, cfg.FourEyes, cfg.RetentionDays
		s.audit = newAuditLog(cfg.AuditDir, configMapAnchor{c: writer, namespace: cfg.Namespace, name: cfg.AuditAnchor}, log.WithName("audit"), time.Now)
	}
	return s, nil
}

// Handler returns the routes behind the security headers and cross-origin protection.
func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "assets/static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", ok)
	mux.HandleFunc("GET /readyz", ok)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("GET /{$}", s.signedIn(s.overviewPage))
	mux.HandleFunc("GET /access", s.signedIn(s.accessPage))
	if s.audit != nil {
		mux.HandleFunc("GET /grants", s.adminOnly(s.grantsPage))
		mux.HandleFunc("GET /grants/new", s.adminOnly(s.grantNewPage))
		mux.HandleFunc("POST /grants", s.adminOnly(s.grantCreate))
		mux.HandleFunc("POST /grants/{name}/extend", s.adminOnly(s.setExpiry(false)))
		mux.HandleFunc("POST /grants/{name}/revoke", s.adminOnly(s.setExpiry(true)))
		mux.HandleFunc("GET /audit", s.adminOnly(s.auditPage))
		mux.HandleFunc("GET /requests", s.signedIn(s.requestsPage))
		mux.HandleFunc("GET /requests/new", s.signedIn(s.requestNewPage))
		mux.HandleFunc("POST /requests", s.signedIn(s.requestCreate))
		mux.HandleFunc("POST /grants/{name}/request", s.signedIn(s.requestExtend))
		mux.HandleFunc("POST /requests/{name}/approve", s.adminOnly(s.decide("approve")))
		mux.HandleFunc("POST /requests/{name}/reject", s.adminOnly(s.decide("reject")))
		mux.HandleFunc("POST /requests/{name}/withdraw", s.signedIn(s.decide("withdraw")))
	}
	return headers(http.NewCrossOriginProtection().Handler(mux))
}

func ok(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// render buffers the page so a template error never sends half a page.
func (s *Server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Requests = s.audit != nil && p.Session != nil
	p.Manage = p.Requests && p.Session.Role == roleAdmin
	if p.Manage {
		// ponytail: one request list per admin page view; read the count from an informer if
		// admins or requests become many.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		counts, err := s.pending(ctx)
		cancel()
		if err != nil {
			s.log.Info("request count failed")
		}
		for _, n := range counts {
			p.Pending += n
		}
	}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error(err, "render page", "page", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// message pages show no session: they also answer sign-in failures and the sign-out.
func (s *Server) message(w http.ResponseWriter, _ *http.Request, status int, heading, text string) {
	s.render(w, status, "message", page{Title: heading, Body: message{Heading: heading, Text: text}})
}
