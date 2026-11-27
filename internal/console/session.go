package console

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	sessionCookie = "__Host-tsunaro-session"
	loginCookie   = "__Host-tsunaro-login"
	sessionTTL    = time.Hour
	loginTTL      = 10 * time.Minute
)

var errSealed = errors.New("sealed value is invalid or expired")

// sealer encrypts and authenticates cookie values. The cookie name is the additional data, so a
// value sealed for one cookie never opens as another.
type sealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

// newSealer takes a 32-byte key (AES-256-GCM).
func newSealer(key []byte, now func() time.Time) (*sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("session key must be 32 bytes")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead, now: now}, nil
}

type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"d"`
}

func (s *sealer) seal(purpose string, v any, ttl time.Duration) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(envelope{Exp: s.now().Add(ttl).Unix(), Data: data})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte(purpose))), nil
}

func (s *sealer) open(purpose, token string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return errSealed
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return errSealed
	}
	var env envelope
	if json.Unmarshal(plain, &env) != nil || s.now().Unix() >= env.Exp {
		return errSealed
	}
	if json.Unmarshal(env.Data, v) != nil {
		return errSealed
	}
	return nil
}

// setCookie writes a sealed host-only cookie; the __Host- prefix requires Secure and Path=/.
func (s *sealer) setCookie(w http.ResponseWriter, name string, v any, ttl time.Duration) error {
	value, err := s.seal(name, v, ttl)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(ttl / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return nil
}

func (s *sealer) readCookie(r *http.Request, name string, v any) error {
	c, err := r.Cookie(name)
	if err != nil {
		return errSealed
	}
	return s.open(name, c.Value, v)
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
