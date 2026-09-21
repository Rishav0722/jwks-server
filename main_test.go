package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGenerateKey(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	key, err := generateKey("test", expiry)
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != "test" || key.Private == nil || !key.ExpiresAt.Equal(expiry) {
		t.Fatal("generated key has incorrect fields")
	}
}

func TestPublicJWK(t *testing.T) {
	key, err := generateKey("abc", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	jwk := publicJWK(key)
	if jwk.Kty != "RSA" || jwk.Kid != "abc" || jwk.Use != "sig" || jwk.Alg != "RS256" {
		t.Fatal("incorrect JWK metadata")
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil || len(n) == 0 {
		t.Fatal("invalid modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil || len(e) == 0 {
		t.Fatal("invalid exponent")
	}
}

func TestJWKSOnlyReturnsUnexpiredKeys(t *testing.T) {
	valid, _ := generateKey("valid", time.Now().Add(time.Hour))
	expired, _ := generateKey("expired", time.Now().Add(-time.Hour))
	store := &KeyStore{keys: []Key{valid, expired}}

	result := store.publicJWKS(time.Now())
	if len(result.Keys) != 1 || result.Keys[0].Kid != "valid" {
		t.Fatalf("unexpected JWKS: %+v", result)
	}
}

func TestJWKSHandler(t *testing.T) {
	store, err := newKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	jwksHandler(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
	var body JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) != 1 || body.Keys[0].Kid != "valid-key" {
		t.Fatalf("unexpected keys: %+v", body.Keys)
	}
}

func TestJWKSRejectsNonGET(t *testing.T) {
	store, _ := newKeyStore()
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	jwksHandler(store)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d", rec.Code)
	}
}

func TestActiveAndExpiredKeys(t *testing.T) {
	valid, _ := generateKey("valid", time.Now().Add(time.Hour))
	expired, _ := generateKey("expired", time.Now().Add(-time.Hour))
	store := &KeyStore{keys: []Key{valid, expired}}

	active, ok := store.activeKey(time.Now())
	if !ok || active.ID != "valid" {
		t.Fatal("active key not found")
	}
	old, ok := store.expiredKey()
	if !ok || old.ID != "expired" {
		t.Fatal("expired key not found")
	}
}

func TestAuthReturnsValidJWT(t *testing.T) {
	store, _ := newKeyStore()
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()
	authHandler(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
	token := strings.TrimSpace(rec.Body.String())
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "valid-key" || header["alg"] != "RS256" {
		t.Fatalf("unexpected header: %+v", header)
	}
}

func TestAuthReturnsExpiredJWTWhenRequested(t *testing.T) {
	store, _ := newKeyStore()
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	rec := httptest.NewRecorder()
	authHandler(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
	parts := strings.Split(strings.TrimSpace(rec.Body.String()), ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	_ = json.Unmarshal(headerBytes, &header)
	if header["kid"] != "expired-key" {
		t.Fatalf("expected expired key, got %+v", header)
	}
}

func TestAuthRejectsNonPOST(t *testing.T) {
	store, _ := newKeyStore()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()
	authHandler(store)(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d", rec.Code)
	}
}

func TestSignJWT(t *testing.T) {
	key, _ := generateKey("sign-test", time.Now().Add(time.Hour))
	token, err := signJWT(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Fatal("invalid JWT structure")
	}
}

func TestActiveKeyMissing(t *testing.T) {
	store := &KeyStore{}
	if _, ok := store.activeKey(time.Now()); ok {
		t.Fatal("expected no active key")
	}
}

func TestExpiredKeyMissing(t *testing.T) {
	store := &KeyStore{}
	if _, ok := store.expiredKey(); ok {
		t.Fatal("expected no expired key")
	}
}

func TestAuthFailsWithoutActiveKey(t *testing.T) {
	store := &KeyStore{}
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()
	authHandler(store)(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d", rec.Code)
	}
}

func TestAuthFailsWithoutExpiredKey(t *testing.T) {
	valid, _ := generateKey("valid", time.Now().Add(time.Hour))
	store := &KeyStore{keys: []Key{valid}}
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	rec := httptest.NewRecorder()
	authHandler(store)(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got status %d", rec.Code)
	}
}

func TestQueryParameterPresence(t *testing.T) {
	withValue := httptest.NewRequest(http.MethodPost, "/auth?expired=false", nil)
	without := httptest.NewRequest(http.MethodPost, "/auth", nil)
	if !hasQueryParameter(withValue, "expired") || hasQueryParameter(without, "expired") {
		t.Fatal("query parameter presence was detected incorrectly")
	}
}

func TestNewServer(t *testing.T) {
	server, err := newServer()
	if err != nil {
		t.Fatal(err)
	}
	if server.Addr != ":8080" || server.Handler == nil {
		t.Fatal("server was not configured correctly")
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	server.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
}
