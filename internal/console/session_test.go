package console

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testSealer(t *testing.T, now *time.Time) *sealer {
	t.Helper()
	s, err := newSealer(bytes.Repeat([]byte{7}, 32), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSealRoundTripAndExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testSealer(t, &now)
	token, err := s.seal(sessionCookie, session{Subject: "abc", Role: roleAdmin}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var got session
	if err := s.open(sessionCookie, token, &got); err != nil || got.Subject != "abc" || got.Role != roleAdmin {
		t.Fatalf("open = %v, %+v", err, got)
	}
	now = now.Add(time.Hour)
	if s.open(sessionCookie, token, &got) == nil {
		t.Fatal("expired value opened")
	}
}

func TestSealRejectsTamperingPurposeAndForeignKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testSealer(t, &now)
	token, _ := s.seal(sessionCookie, session{Subject: "abc"}, time.Hour)
	raw, _ := base64.RawURLEncoding.DecodeString(token)
	raw[len(raw)-1] ^= 1
	var got session
	for name, c := range map[string]struct{ purpose, token string }{
		"tampered":      {sessionCookie, base64.RawURLEncoding.EncodeToString(raw)},
		"other purpose": {loginCookie, token},
		"not base64":    {sessionCookie, "%%%"},
		"too short":     {sessionCookie, "AAAA"},
	} {
		if s.open(c.purpose, c.token, &got) == nil {
			t.Errorf("%s: opened", name)
		}
	}
	other, _ := newSealer(bytes.Repeat([]byte{8}, 32), func() time.Time { return now })
	if other.open(sessionCookie, token, &got) == nil {
		t.Error("foreign key opened")
	}
	if _, err := newSealer(make([]byte, 16), time.Now); err == nil {
		t.Error("16-byte key accepted")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testSealer(t, &now)
	rec := httptest.NewRecorder()
	if err := s.setCookie(rec, sessionCookie, session{Subject: "abc"}, sessionTTL); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	if c.Name != "__Host-tsunaro-session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 3600 {
		t.Fatalf("cookie attributes: %+v", c)
	}
}
