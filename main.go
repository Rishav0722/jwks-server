package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	port      = ":8080"
	issuer    = "jwks-server"
	algorithm = "RS256"
)

type Key struct {
	ID        string
	Private   *rsa.PrivateKey
	ExpiresAt time.Time
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type KeyStore struct {
	mu   sync.RWMutex
	keys []Key
}

func newKeyStore() (*KeyStore, error) {
	now := time.Now()
	valid, err := generateKey("valid-key", now.Add(24*time.Hour))
	if err != nil {
		return nil, err
	}
	expired, err := generateKey("expired-key", now.Add(-1*time.Hour))
	if err != nil {
		return nil, err
	}
	return &KeyStore{keys: []Key{valid, expired}}, nil
}

func generateKey(kid string, expiry time.Time) (Key, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Key{}, err
	}
	return Key{ID: kid, Private: private, ExpiresAt: expiry}, nil
}

func (s *KeyStore) activeKey(now time.Time) (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.keys {
		if now.Before(key.ExpiresAt) {
			return key, true
		}
	}
	return Key{}, false
}

func (s *KeyStore) expiredKey() (Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.keys {
		if !time.Now().Before(key.ExpiresAt) {
			return key, true
		}
	}
	return Key{}, false
}

func (s *KeyStore) publicJWKS(now time.Time) JWKS {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := JWKS{Keys: make([]JWK, 0, len(s.keys))}
	for _, key := range s.keys {
		if now.Before(key.ExpiresAt) {
			result.Keys = append(result.Keys, publicJWK(key))
		}
	}
	return result
}

func publicJWK(key Key) JWK {
	public := &key.Private.PublicKey
	return JWK{
		Kty: "RSA",
		Kid: key.ID,
		Use: "sig",
		Alg: algorithm,
		N:   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}
}

func main() {
	server, err := newServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("JWKS server listening on http://localhost%s", port)
	log.Fatal(server.ListenAndServe())
}

func newServer() (*http.Server, error) {
	store, err := newKeyStore()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler(store))
	mux.HandleFunc("/auth", authHandler(store))

	return &http.Server{Addr: port, Handler: mux}, nil
}

func jwksHandler(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(store.publicJWKS(time.Now())); err != nil {
			log.Printf("encoding JWKS: %v", err)
		}
	}
}

func authHandler(store *KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		key, ok := store.activeKey(time.Now())
		if hasQueryParameter(r, "expired") {
			key, ok = store.expiredKey()
		}
		if !ok {
			http.Error(w, "required signing key is unavailable", http.StatusInternalServerError)
			return
		}

		token, err := signJWT(key, time.Now())
		if err != nil {
			http.Error(w, "could not issue token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(token))
	}
}

func hasQueryParameter(r *http.Request, name string) bool {
	_, exists := r.URL.Query()[name]
	return exists
}

func signJWT(key Key, now time.Time) (string, error) {
	header := map[string]string{
		"alg": algorithm,
		"typ": "JWT",
		"kid": key.ID,
	}
	claims := map[string]interface{}{
		"iss": issuer,
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": key.ExpiresAt.Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.Private, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
