package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	roleAdmin = "admin"
	roleUser  = "user"
)

// Config is the console's runtime configuration. URL is the public base URL; the IdP redirects to
// URL + "/auth/callback".
type Config struct {
	URL          string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	AdminGroup   string
	// Empty: every signed-in person is a user.
	UserGroup string
	// OperatorURL is the base URL of the operator's console API; TokenFile holds the projected
	// ServiceAccount token presented to it.
	OperatorURL string
	TokenFile   string
	// AuditDir switches access management on: admins manage TailnetGrants, and every change is
	// first appended to AuditDir/audit.jsonl, whose head the ConfigMap AuditAnchor in Namespace
	// keeps. Empty: the console only reads.
	AuditDir    string
	AuditAnchor string
	Namespace   string
	// FourEyes makes admins request their own grants and extensions: another admin approves
	// them, and a user's request needs two admins.
	FourEyes bool
}

// Validate never echoes the secret.
func (c Config) Validate() error {
	var missing []string
	for name, v := range map[string]string{"URL": c.URL, "issuer": c.Issuer, "client ID": c.ClientID,
		"client secret": c.ClientSecret, "admin group": c.AdminGroup, "operator URL": c.OperatorURL, "token file": c.TokenFile} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("console configuration lacks %s", strings.Join(missing, ", "))
	}
	for name, v := range map[string]string{"URL": c.URL, "issuer": c.Issuer} {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("console %s must be an https URL without query or fragment", name)
		}
		// The routes and the __Host- cookie live at "/": the console cannot sit below a path.
		if name == "URL" && u.Path != "" && u.Path != "/" {
			return errors.New("console URL must not have a path")
		}
	}
	if u, err := url.Parse(c.OperatorURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("console operator URL must be an http(s) URL without path, query or credentials")
	}
	if c.AuditDir != "" && (strings.TrimSpace(c.AuditAnchor) == "" || strings.TrimSpace(c.Namespace) == "") {
		return errors.New("console access management needs the audit anchor ConfigMap and its namespace")
	}
	if c.FourEyes && c.AuditDir == "" {
		return errors.New("console four-eyes approval needs access management")
	}
	if !slices.Contains(c.Scopes, oidc.ScopeOpenID) {
		return errors.New("console scopes must contain openid")
	}
	return nil
}

// session is the content of the session cookie. Tokens are not kept.
type session struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Role    string `json:"role"`
}

type loginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Return   string `json:"return"`
}

type identity struct {
	Subject           string    `json:"sub"`
	Name              string    `json:"name"`
	PreferredUsername string    `json:"preferred_username"`
	Groups            *[]string `json:"groups"`
}

// oidcClient is discovered on the first login, not at start: an unreachable IdP must not keep the
// console from becoming ready.
type oidcClient struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

type authenticator struct {
	cfg    Config
	seal   *sealer
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	oc     *oidcClient
}

func (a *authenticator) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, a.client)
}

func (a *authenticator) discover() (*oidcClient, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.oc != nil {
		return a.oc, nil
	}
	// The provider keeps this context for later key fetches, so it must outlive the request.
	p, err := oidc.NewProvider(a.ctx(context.Background()), a.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	a.oc = &oidcClient{
		provider: p,
		verifier: p.Verifier(&oidc.Config{ClientID: a.cfg.ClientID, Now: a.now}),
		oauth: oauth2.Config{ClientID: a.cfg.ClientID, ClientSecret: a.cfg.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: strings.TrimSuffix(a.cfg.URL, "/") + "/auth/callback", Scopes: a.cfg.Scopes},
	}
	return a.oc, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeReturn accepts only a local absolute path; anything else returns to the overview.
func safeReturn(p string) string {
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return "/"
	}
	return p
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	oc, err := s.auth.discover()
	if err != nil {
		s.log.Info("identity provider discovery failed")
		s.message(w, r, http.StatusServiceUnavailable, "Sign-in unavailable", "The identity provider cannot be reached. Try again later.")
		return
	}
	st := loginState{Verifier: oauth2.GenerateVerifier(), Return: safeReturn(r.URL.Query().Get("return"))}
	if st.State, err = randomToken(); err == nil {
		st.Nonce, err = randomToken()
	}
	if err == nil {
		err = s.auth.seal.setCookie(w, loginCookie, st, loginTTL)
	}
	if err != nil {
		s.message(w, r, http.StatusInternalServerError, "Sign-in failed", "The console could not start the sign-in.")
		return
	}
	http.Redirect(w, r, oc.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	var st loginState
	err := s.auth.seal.readCookie(r, loginCookie, &st)
	clearCookie(w, loginCookie)
	q := r.URL.Query()
	if err != nil || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 || q.Get("code") == "" {
		s.log.Info("sign-in rejected", "result", "state")
		s.message(w, r, http.StatusBadRequest, "Sign-in failed", "The sign-in expired or did not start here. Sign in again.")
		return
	}
	sess, err := s.authenticate(r.Context(), q.Get("code"), st)
	if err != nil {
		s.log.Info("sign-in rejected", "result", "token")
		s.message(w, r, http.StatusUnauthorized, "Sign-in failed", "The identity provider's answer could not be verified. Sign in again.")
		return
	}
	if sess.Role == "" {
		s.log.Info("sign-in rejected", "result", "no role")
		s.message(w, r, http.StatusForbidden, "No access", "Your account is in neither the admin group nor the user group of this console.")
		return
	}
	if err := s.auth.seal.setCookie(w, sessionCookie, sess, sessionTTL); err != nil {
		s.message(w, r, http.StatusInternalServerError, "Sign-in failed", "The console could not create the session.")
		return
	}
	s.log.Info("signed in", "role", sess.Role)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

func (s *Server) authenticate(ctx context.Context, code string, st loginState) (session, error) {
	oc, err := s.auth.discover()
	if err != nil {
		return session{}, err
	}
	ctx = s.auth.ctx(ctx)
	tok, err := oc.oauth.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return session{}, err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return session{}, errors.New("no id_token")
	}
	idt, err := oc.verifier.Verify(ctx, raw)
	if err != nil {
		return session{}, err
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return session{}, errors.New("nonce mismatch")
	}
	var id identity
	if err := idt.Claims(&id); err != nil {
		return session{}, err
	}
	if id.Groups == nil {
		info, err := oc.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return session{}, err
		}
		if info.Subject != idt.Subject {
			return session{}, errors.New("userinfo subject mismatch")
		}
		var extra identity
		if err := info.Claims(&extra); err != nil {
			return session{}, err
		}
		id.Groups = extra.Groups
	}
	var groups []string
	if id.Groups != nil {
		groups = *id.Groups
	}
	name := id.Name
	if name == "" {
		name = id.PreferredUsername
	}
	return session{Issuer: idt.Issuer, Subject: idt.Subject, Name: name, Role: s.role(groups)}, nil
}

// role: admin includes user; an empty user group admits every signed-in person.
func (s *Server) role(groups []string) string {
	switch {
	case slices.Contains(groups, s.auth.cfg.AdminGroup):
		return roleAdmin
	case s.auth.cfg.UserGroup == "" || slices.Contains(groups, s.auth.cfg.UserGroup):
		return roleUser
	}
	return ""
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, sessionCookie)
	s.message(w, r, http.StatusOK, "Signed out", "You are signed out of the console. Your session at the identity provider stays.")
}

// signedIn serves page only with a valid session; otherwise it starts the sign-in and returns here.
func (s *Server) signedIn(page func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess session
		if s.auth.seal.readCookie(r, sessionCookie, &sess) != nil || sess.Role == "" {
			http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		page(w, r, &sess)
	}
}

// adminOnly serves the page to admins and answers everybody else with 403 (rule 1).
func (s *Server) adminOnly(page func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return s.signedIn(func(w http.ResponseWriter, r *http.Request, sess *session) {
		if sess.Role != roleAdmin {
			s.message(w, r, http.StatusForbidden, "Admins only", "Only console admins manage grants, decide requests and read the audit log.")
			return
		}
		page(w, r, sess)
	})
}
