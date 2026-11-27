// Package console serves the read-only web console: OIDC sign-in, roles from the groups claim and
// an overview of tailnets, spokes, ingresses and sites read from the Kubernetes API.
package console

import (
	"bytes"
	"crypto/rand"
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

//go:embed assets
var assets embed.FS

const contentSecurityPolicy = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// Server is the console's HTTP surface.
type Server struct {
	auth   *authenticator
	reader client.Reader
	log    logr.Logger
	pages  map[string]*template.Template
}

type page struct {
	Title   string
	Session *session
	Body    any
}

type message struct{ Heading, Text string }

// New creates the server with a fresh session key: a restart signs everybody out.
func New(cfg Config, reader client.Reader, log logr.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
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
	for _, name := range []string{"overview", "message"} {
		t, err := template.ParseFS(assets, "assets/layout.html", "assets/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return &Server{
		auth:   &authenticator{cfg: cfg, seal: seal, now: time.Now, client: &http.Client{Timeout: 10 * time.Second}},
		reader: reader, log: log, pages: pages,
	}, nil
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
