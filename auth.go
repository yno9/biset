package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Client-side counterpart of jmapsmtp's cryptenv package.
//
//   password ─Argon2id(salt)─> wrap_key
//   wrap_key ─AES-GCM-open──> master_secret
//   master_secret ─HKDF("auth/v1")─> auth_token
//   master_secret ─HKDF("enc/v1") ─> KEK

const (
	hkdfInfoAuth = "biset-jmapsmtp/auth/v1"
	hkdfInfoKEK  = "biset-jmapsmtp/enc/v1"
)

type envelopeJSON struct {
	Version       int             `json:"v"`
	Salt          string          `json:"salt"`
	KDF           envelopeKDF     `json:"kdf"`
	WrappedSecret string          `json:"wrapped_secret"`
	AuthTokenHash string          `json:"auth_token_hash"`
}

type envelopeKDF struct {
	Time    uint32 `json:"t"`
	Memory  uint32 `json:"m"`
	Threads uint8  `json:"p"`
}

// fetchEnvelope retrieves the per-account envelope from the relay.
// URL form: <relay-base>/auth/envelope?email=<addr>. The relay base is derived
// by stripping a trailing /.well-known/jmap if present.
func fetchEnvelope(sessionURL, email string) (*envelopeJSON, error) {
	base := strings.TrimSuffix(sessionURL, "/.well-known/jmap")
	base = strings.TrimSuffix(base, "/")
	url := fmt.Sprintf("%s/auth/envelope?email=%s", base, email)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var env envelopeJSON
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, err
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	return &env, nil
}

// unsealEnvelope opens the envelope using password, returning (auth_token, kek).
// Returns an error on wrong password (AEAD tag mismatch).
func unsealEnvelope(env *envelopeJSON, password string) (authToken, kek []byte, err error) {
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("salt: %w", err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(env.WrappedSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("wrapped: %w", err)
	}
	wantHash, err := base64.StdEncoding.DecodeString(env.AuthTokenHash)
	if err != nil {
		return nil, nil, fmt.Errorf("hash: %w", err)
	}

	wrapKey := argon2.IDKey([]byte(password), salt, env.KDF.Time, env.KDF.Memory, env.KDF.Threads, 32)
	masterSecret, err := aesGCMOpen(wrapKey, wrapped)
	if err != nil {
		return nil, nil, errors.New("wrong password")
	}

	authToken = hkdfBytes(masterSecret, hkdfInfoAuth, 32)
	kek = hkdfBytes(masterSecret, hkdfInfoKEK, 32)

	// Sanity check: derived auth_token must match the published hash.
	got := sha256.Sum256(authToken)
	if subtle.ConstantTimeCompare(got[:], wantHash) != 1 {
		return nil, nil, errors.New("envelope auth_token_hash mismatch")
	}
	return authToken, kek, nil
}

// loginViaEnvelope fetches the envelope and unseals it in one shot.
// Returns base64(auth_token) ready for HTTP Basic Auth and the raw KEK bytes.
func loginViaEnvelope(sessionURL, email, password string) (authTokenB64 string, kek []byte, err error) {
	env, err := fetchEnvelope(sessionURL, email)
	if err != nil {
		return "", nil, fmt.Errorf("fetch envelope: %w", err)
	}
	authToken, kek, err := unsealEnvelope(env, password)
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(authToken), kek, nil
}

// ── internals ─────────────────────────────────────────────────────────────────

func aesGCMOpen(key, sealed []byte) ([]byte, error) {
	if len(sealed) < 12 {
		return nil, errors.New("sealed too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := sealed[:12], sealed[12:]
	return aead.Open(nil, nonce, ct, nil)
}

func hkdfBytes(secret []byte, info string, n int) []byte {
	r := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

// ── PGP privkey blob (server-stored) ──────────────────────────────────────────

// New blob format (matches biset-ui): {"iv": b64, "ct": b64}. AES-GCM with
// kek as the 32-byte key, email as additional-data.

type privkeyBlobNew struct {
	IV string `json:"iv"`
	CT string `json:"ct"`
}

func decryptPrivkeyBlobKEK(jsonStr string, kek []byte, email string) (string, error) {
	var b privkeyBlobNew
	if err := json.Unmarshal([]byte(jsonStr), &b); err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(b.IV)
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(b.CT)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, ct, []byte(email))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func encryptPrivkeyBlobKEK(armoredPriv string, kek []byte, email string) (string, error) {
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, iv, []byte(armoredPriv), []byte(email))
	out, err := json.Marshal(privkeyBlobNew{
		IV: base64.StdEncoding.EncodeToString(iv),
		CT: base64.StdEncoding.EncodeToString(ct),
	})
	return string(out), err
}
