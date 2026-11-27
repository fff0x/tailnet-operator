package console

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tnv1 "tsunaro.io/tailnet-operator/api/v1alpha1"
)

const (
	testSubject = "subject-7f3a"
	testName    = "Alice Example"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS, token endpoint with PKCE S256, UserInfo.
type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]issued
	info  map[string]any // UserInfo answer
}

type issued struct {
	challenge string
	claims    map[string]any
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, codes: map[string]issued{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		u := idp.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": u, "authorization_endpoint": u + "/authorize",
			"token_endpoint": u + "/token", "jwks_uri": u + "/jwks", "userinfo_endpoint": u + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig",
			"kid": "k1", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		c, ok := idp.codes[r.Form.Get("code")]
		delete(idp.codes, r.Form.Get("code"))
		idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if user, pass, _ := r.BasicAuth(); !ok || user != "console" || pass != "secret" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": idp.sign(t, c.claims)})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.info)
	})
	idp.srv = httptest.NewTLSServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := tnv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

type testConsole struct {
	*Server
	idp  *fakeIdP
	h    http.Handler
	logs *strings.Builder
}

func newTestConsole(t *testing.T, mutate func(*Config), objs ...client.Object) *testConsole {
	t.Helper()
	idp := newFakeIdP(t)
	cfg := Config{URL: "https://console.example", Issuer: idp.srv.URL, ClientID: "console", ClientSecret: "secret",
		Scopes: []string{"openid", "profile", "groups"}, AdminGroup: "admins", UserGroup: "users",
		OperatorURL: "http://127.0.0.1:1", TokenFile: "/nonexistent"}
	if mutate != nil {
		mutate(&cfg)
	}
	logs := &strings.Builder{}
	var mu sync.Mutex
	log := funcr.New(func(prefix, args string) { mu.Lock(); logs.WriteString(prefix + args + "\n"); mu.Unlock() }, funcr.Options{})
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	s, err := New(cfg, reader, log)
	if err != nil {
		t.Fatal(err)
	}
	s.auth.client = idp.srv.Client()
	return &testConsole{Server: s, idp: idp, h: s.Handler(), logs: logs}
}

func (c *testConsole) do(t *testing.T, method, target string, cookies []*http.Cookie, headers ...string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "https://console.example"+target, nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec.Result()
}

func cookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// flow is one sign-in up to the callback; adjust changes what the IdP issues.
type flow struct {
	returnTo string
	adjust   func(claims map[string]any, challenge *string, state *string)
}

func (c *testConsole) signIn(t *testing.T, f flow, claims map[string]any) *http.Response {
	t.Helper()
	resp := c.do(t, http.MethodGet, "/auth/login?return="+url.QueryEscape(f.returnTo), nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), c.idp.srv.URL+"/authorize?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" ||
		q.Get("redirect_uri") != "https://console.example/auth/callback" || q.Get("client_id") != "console" {
		t.Fatalf("authorize redirect: %s", loc)
	}
	login := cookie(resp, loginCookie)
	if login == nil || login.MaxAge != 600 {
		t.Fatalf("login cookie: %+v", login)
	}
	base := map[string]any{"iss": c.idp.srv.URL, "aud": "console", "sub": testSubject, "name": testName,
		"nonce": q.Get("nonce"), "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		base[k] = v
	}
	challenge, state := q.Get("code_challenge"), q.Get("state")
	if f.adjust != nil {
		f.adjust(base, &challenge, &state)
	}
	c.idp.mu.Lock()
	c.idp.codes["code-1"] = issued{challenge: challenge, claims: base}
	c.idp.mu.Unlock()
	return c.do(t, http.MethodGet, "/auth/callback?code=code-1&state="+url.QueryEscape(state), []*http.Cookie{login})
}

func TestSignInRoles(t *testing.T) {
	for name, tc := range map[string]struct {
		groups    any
		userGroup string
		role      string
		status    int
	}{
		"admin":                   {[]string{"admins"}, "users", roleAdmin, http.StatusFound},
		"admin includes user":     {[]string{"admins", "users"}, "users", roleAdmin, http.StatusFound},
		"user":                    {[]string{"users"}, "users", roleUser, http.StatusFound},
		"no role":                 {[]string{"other"}, "users", "", http.StatusForbidden},
		"empty groups":            {[]string{}, "users", "", http.StatusForbidden},
		"empty user group admits": {[]string{"other"}, "", roleUser, http.StatusFound},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestConsole(t, func(cfg *Config) { cfg.UserGroup = tc.userGroup })
			resp := c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": tc.groups})
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			if lc := cookie(resp, loginCookie); lc == nil || lc.MaxAge >= 0 {
				t.Fatal("login cookie not cleared")
			}
			sc := cookie(resp, sessionCookie)
			if tc.role == "" {
				if sc != nil {
					t.Fatal("session without role")
				}
				return
			}
			var got session
			if sc == nil || c.auth.seal.open(sessionCookie, sc.Value, &got) != nil {
				t.Fatal("no session cookie")
			}
			if got.Role != tc.role || got.Subject != testSubject || got.Issuer != c.idp.srv.URL || got.Name != testName {
				t.Fatalf("session %+v", got)
			}
			if resp.Header.Get("Location") != "/" {
				t.Fatalf("redirect %q", resp.Header.Get("Location"))
			}
		})
	}
}

func TestSignInGroupsFromUserInfo(t *testing.T) {
	c := newTestConsole(t, nil)
	c.idp.info = map[string]any{"sub": testSubject, "groups": []string{"admins"}}
	resp := c.signIn(t, flow{returnTo: "/"}, nil)
	var got session
	if sc := cookie(resp, sessionCookie); sc == nil || c.auth.seal.open(sessionCookie, sc.Value, &got) != nil || got.Role != roleAdmin {
		t.Fatalf("status %d, session %+v", resp.StatusCode, got)
	}
	c.idp.info = map[string]any{"sub": "someone-else", "groups": []string{"admins"}}
	if resp := c.signIn(t, flow{returnTo: "/"}, nil); resp.StatusCode != http.StatusUnauthorized || cookie(resp, sessionCookie) != nil {
		t.Fatalf("foreign UserInfo subject accepted: %d", resp.StatusCode)
	}
}

func TestSignInRejections(t *testing.T) {
	groups := map[string]any{"groups": []string{"admins"}}
	for name, tc := range map[string]struct {
		adjust func(claims map[string]any, challenge, state *string)
		status int
	}{
		"wrong state":    {func(_ map[string]any, _, s *string) { *s = "forged" }, http.StatusBadRequest},
		"wrong nonce":    {func(c map[string]any, _, _ *string) { c["nonce"] = "forged" }, http.StatusUnauthorized},
		"wrong audience": {func(c map[string]any, _, _ *string) { c["aud"] = "other-client" }, http.StatusUnauthorized},
		"wrong issuer":   {func(c map[string]any, _, _ *string) { c["iss"] = "https://evil.example" }, http.StatusUnauthorized},
		"expired":        {func(c map[string]any, _, _ *string) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, http.StatusUnauthorized},
		"wrong PKCE":     {func(_ map[string]any, ch, _ *string) { *ch = "not-the-challenge" }, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestConsole(t, nil)
			resp := c.signIn(t, flow{returnTo: "/", adjust: tc.adjust}, groups)
			if resp.StatusCode != tc.status || cookie(resp, sessionCookie) != nil {
				t.Fatalf("status %d (want %d), session %v", resp.StatusCode, tc.status, cookie(resp, sessionCookie) != nil)
			}
		})
	}
	t.Run("no login cookie", func(t *testing.T) {
		c := newTestConsole(t, nil)
		if resp := c.do(t, http.MethodGet, "/auth/callback?code=x&state=y", nil); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("expired login cookie", func(t *testing.T) {
		c := newTestConsole(t, nil)
		resp := c.signIn(t, flow{returnTo: "/", adjust: func(map[string]any, *string, *string) {
			c.auth.seal.now = func() time.Time { return time.Now().Add(loginTTL) }
		}}, groups)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func TestSignInReturnTarget(t *testing.T) {
	c := newTestConsole(t, nil)
	groups := map[string]any{"groups": []string{"admins"}}
	if got := c.signIn(t, flow{returnTo: "/?tab=sites"}, groups).Header.Get("Location"); got != "/?tab=sites" {
		t.Fatalf("local return lost: %q", got)
	}
	if got := c.signIn(t, flow{returnTo: "https://evil.example/"}, groups).Header.Get("Location"); got != "/" {
		t.Fatalf("foreign return followed: %q", got)
	}
	for in, want := range map[string]string{"/": "/", "/a?b=c": "/a?b=c", "": "/", "//evil.example": "/",
		"/\\evil.example": "/", "https://evil.example": "/", "evil": "/", "/a\r\nSet-Cookie:x": "/", "javascript:alert(1)": "/"} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPagesRequireSession(t *testing.T) {
	c := newTestConsole(t, nil)
	resp := c.do(t, http.MethodGet, "/?x=1", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/auth/login?return="+url.QueryEscape("/?x=1") {
		t.Fatalf("status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	forged := &http.Cookie{Name: sessionCookie, Value: "forged"}
	if resp := c.do(t, http.MethodGet, "/", []*http.Cookie{forged}); resp.StatusCode != http.StatusFound {
		t.Fatalf("forged session served: %d", resp.StatusCode)
	}
	resp = c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"users"}})
	sc := cookie(resp, sessionCookie)
	if resp := c.do(t, http.MethodGet, "/", []*http.Cookie{sc}); resp.StatusCode != http.StatusOK {
		t.Fatalf("signed-in overview: %d", resp.StatusCode)
	}
	c.auth.seal.now = func() time.Time { return time.Now().Add(sessionTTL) }
	if resp := c.do(t, http.MethodGet, "/", []*http.Cookie{sc}); resp.StatusCode != http.StatusFound {
		t.Fatalf("expired session served: %d", resp.StatusCode)
	}
}

func TestSignOut(t *testing.T) {
	c := newTestConsole(t, nil)
	sc := cookie(c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}}), sessionCookie)
	if resp := c.do(t, http.MethodPost, "/auth/logout", []*http.Cookie{sc}, "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden || cookie(resp, sessionCookie) != nil {
		t.Fatalf("cross-site sign-out accepted: %d", resp.StatusCode)
	}
	if resp := c.do(t, http.MethodGet, "/auth/logout", []*http.Cookie{sc}); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET sign-out: %d", resp.StatusCode)
	}
	resp := c.do(t, http.MethodPost, "/auth/logout", []*http.Cookie{sc}, "Sec-Fetch-Site", "same-origin")
	if cleared := cookie(resp, sessionCookie); resp.StatusCode != http.StatusOK || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("sign-out: %d, cookie %+v", resp.StatusCode, cleared)
	}
}

func TestDiscoveryFailureKeepsConsoleUp(t *testing.T) {
	c := newTestConsole(t, nil)
	c.idp.srv.Close()
	if resp := c.do(t, http.MethodGet, "/auth/login", nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login with unreachable IdP: %d", resp.StatusCode)
	}
	if resp := c.do(t, http.MethodGet, "/readyz", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz: %d", resp.StatusCode)
	}
}

func TestLogsCarryNoIdentity(t *testing.T) {
	c := newTestConsole(t, nil)
	c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"admins"}, "email": "alice@example.com"})
	c.signIn(t, flow{returnTo: "/", adjust: func(cl map[string]any, _, _ *string) { cl["nonce"] = "x" }}, map[string]any{"groups": []string{"admins"}})
	c.signIn(t, flow{returnTo: "/"}, map[string]any{"groups": []string{"other"}})
	logs := c.logs.String()
	if !strings.Contains(logs, "signed in") || !strings.Contains(logs, "sign-in rejected") {
		t.Fatalf("expected sign-in log lines, got %q", logs)
	}
	for _, secret := range []string{testSubject, testName, "alice@example.com", "secret", "code-1"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log contains %q: %s", secret, logs)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{URL: "https://console.example", Issuer: "https://id.example", ClientID: "c", ClientSecret: "s3cr3t",
		Scopes: []string{"openid"}, AdminGroup: "admins", OperatorURL: "http://tsunaro-console-api.operator.svc:8082", TokenFile: "/token"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"no URL":          func(c *Config) { c.URL = "" },
		"http URL":        func(c *Config) { c.URL = "http://console.example" },
		"URL with query":  func(c *Config) { c.URL = "https://console.example/?a=b" },
		"URL with path":   func(c *Config) { c.URL = "https://console.example/console" },
		"http issuer":     func(c *Config) { c.Issuer = "http://id.example" },
		"no client ID":    func(c *Config) { c.ClientID = "" },
		"no secret":       func(c *Config) { c.ClientSecret = " " },
		"no admin group":  func(c *Config) { c.AdminGroup = "" },
		"no openid scope": func(c *Config) { c.Scopes = []string{"profile"} },
		"no operator URL": func(c *Config) { c.OperatorURL = "" },
		"operator path":   func(c *Config) { c.OperatorURL = "http://op:8082/v1" },
		"operator scheme": func(c *Config) { c.OperatorURL = "ftp://op:8082" },
		"operator creds":  func(c *Config) { c.OperatorURL = "http://u:p@op:8082" },
		"no token file":   func(c *Config) { c.TokenFile = "" },
	} {
		c := good
		mutate(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: error echoes the secret", name)
		}
	}
	if _, err := New(Config{}, nil, logr.Discard()); err == nil {
		t.Error("New accepted an empty configuration")
	}
}
