package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"biset/vault"
)

// type aliases to avoid pulling vault. into every signature in this file.
type (
	Message   = vault.Message
	BodyValue = vault.BodyValue
)

// EnsureAccountKey loads (or generates+uploads) a PGP keypair for one account.
// On success the armored private key lives at ~/.biset/keys/<email>.asc.
func EnsureAccountKey(r *Relay) error {
	if r.accountEmail == "" || r.accountPlainPW == "" {
		return nil // not a per-account relay
	}
	path, err := localPrivkeyPath(r.accountEmail)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil // already have it locally
	}

	if len(r.kek) == 0 {
		return fmt.Errorf("no KEK for %s (envelope login required)", r.accountEmail)
	}

	// Try to fetch encrypted privkey from server.
	blob, err := fetchEncryptedPrivkey(r)
	if err == nil && blob != "" {
		armored, err := decryptPrivkeyBlobKEK(blob, r.kek, r.accountEmail)
		if err != nil {
			return fmt.Errorf("decrypt privkey for %s: %w", r.accountEmail, err)
		}
		if err := savePrivkeyLocal(path, armored); err != nil {
			return err
		}
		log.Printf("[pgp] recovered keypair from server for %s", r.accountEmail)
		return uploadPublicKey(r, derivePubkeyFromPriv(armored))
	}

	// Generate new keypair.
	armoredPriv, armoredPub, err := generateKeypair(r.accountEmail)
	if err != nil {
		return fmt.Errorf("gen keypair for %s: %w", r.accountEmail, err)
	}
	if err := savePrivkeyLocal(path, armoredPriv); err != nil {
		return err
	}
	encBlob, err := encryptPrivkeyBlobKEK(armoredPriv, r.kek, r.accountEmail)
	if err != nil {
		return err
	}
	if err := uploadEncryptedPrivkey(r, encBlob); err != nil {
		log.Printf("[pgp] upload privkey failed for %s: %v", r.accountEmail, err)
	}
	if err := uploadPublicKey(r, armoredPub); err != nil {
		log.Printf("[pgp] upload pubkey failed for %s: %v", r.accountEmail, err)
	}
	log.Printf("[pgp] generated new keypair for %s", r.accountEmail)
	return nil
}

func localPrivkeyPath(email string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".biset", "keys")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, email+".asc"), nil
}

func savePrivkeyLocal(path, armored string) error {
	return os.WriteFile(path, []byte(armored), 0600)
}

func loadPrivkeyLocal(email string) (string, error) {
	path, err := localPrivkeyPath(email)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

func basicAuthHeader(email, authToken string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(email+":"+authToken))
}

func pgpEndpoint(relayURL, path string) string {
	u := strings.TrimSuffix(relayURL, "/.well-known/jmap")
	u = strings.TrimSuffix(u, "/")
	return u + path
}

func fetchEncryptedPrivkey(r *Relay) (string, error) {
	req, err := http.NewRequest("GET", pgpEndpoint(r.cfg.URL, "/pgp/privkey"), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", basicAuthHeader(r.accountEmail, r.cfg.Password))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func uploadEncryptedPrivkey(r *Relay, blob string) error {
	req, err := http.NewRequest("PUT", pgpEndpoint(r.cfg.URL, "/pgp/privkey"), strings.NewReader(blob))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", basicAuthHeader(r.accountEmail, r.cfg.Password))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func uploadPublicKey(r *Relay, armoredPub string) error {
	req, err := http.NewRequest("PUT", pgpEndpoint(r.cfg.URL, "/pgp/pubkey"), strings.NewReader(armoredPub))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", basicAuthHeader(r.accountEmail, r.cfg.Password))
	req.Header.Set("Content-Type", "application/pgp-keys")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// ── crypto ────────────────────────────────────────────────────────────────────
//
// PGP private key blob encryption uses cryptenv KEK directly (no PBKDF2).
// See auth.go for {encrypt,decrypt}PrivkeyBlobKEK.

// generateKeypair creates an ed25519/cv25519 OpenPGP keypair for the given email.
// Returns (armoredPrivate, armoredPublic, error).
func generateKeypair(email string) (string, string, error) {
	name := email
	if i := strings.IndexByte(email, '@'); i > 0 {
		name = email[:i]
	}
	cfg := &packet.Config{
		DefaultHash:   crypto.SHA256,
		Algorithm:     packet.PubKeyAlgoEdDSA,
		Curve:         packet.Curve25519,
		Time:          func() time.Time { return time.Now() },
		DefaultCipher: packet.CipherAES256,
	}
	entity, err := openpgp.NewEntity(name, "biset", email, cfg)
	if err != nil {
		return "", "", err
	}
	var privBuf bytes.Buffer
	aw, err := armor.Encode(&privBuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", "", err
	}
	if err := entity.SerializePrivate(aw, nil); err != nil {
		return "", "", err
	}
	aw.Close()

	var pubBuf bytes.Buffer
	aw2, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", "", err
	}
	if err := entity.Serialize(aw2); err != nil {
		return "", "", err
	}
	aw2.Close()
	return privBuf.String(), pubBuf.String(), nil
}

// DecryptMessageBodies replaces PGP-encrypted bodies in messages with their
// decrypted plaintext (stripping Protected Headers / decoding CTE). Uses the
// private key at ~/.biset/keys/<email>.asc.
func DecryptMessageBodies(messages []Message, email string) {
	if email == "" {
		return
	}
	armoredPriv, err := loadPrivkeyLocal(email)
	if err != nil {
		return
	}
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPriv))
	if err != nil || len(entities) == 0 {
		return
	}
	for i := range messages {
		decryptMessageInPlace(&messages[i], entities)
	}
}

func decryptMessageInPlace(m *Message, keyring openpgp.EntityList) {
	body := messageBody(*m)
	if !strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
		return
	}
	start := strings.Index(body, "-----BEGIN PGP MESSAGE-----")
	end := strings.Index(body, "-----END PGP MESSAGE-----")
	if start < 0 || end < 0 {
		return
	}
	pgpBlock := body[start : end+len("-----END PGP MESSAGE-----")]
	block, err := armor.Decode(strings.NewReader(pgpBlock))
	if err != nil {
		return
	}
	md, err := openpgp.ReadMessage(block.Body, keyring, nil, nil)
	if err != nil {
		return
	}
	plain, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return
	}
	cleaned, innerInReplyTo := stripMIMEHeadersAndExtract(string(plain))
	replaceMessageBody(m, cleaned)
	// Adopt Protected Headers' In-Reply-To and clear ThreadID so biset's
	// Store re-resolves the thread via InReplyTo chain.
	if innerInReplyTo != "" && len(m.InReplyTo) == 0 {
		m.InReplyTo = []string{innerInReplyTo}
		m.ThreadID = ""
	}
}

func messageBody(m Message) string {
	if len(m.TextBody) == 0 || m.TextBody[0] == nil {
		return ""
	}
	bv, ok := m.BodyValues[m.TextBody[0].PartID]
	if !ok || bv == nil {
		return ""
	}
	return bv.Value
}

func replaceMessageBody(m *Message, body string) {
	if len(m.TextBody) == 0 || m.TextBody[0] == nil {
		return
	}
	pid := m.TextBody[0].PartID
	if m.BodyValues == nil {
		return
	}
	m.BodyValues[pid] = &BodyValue{Value: body}
}

// stripMIMEHeaders mirrors biset-ui parseMIME: if the decrypted content starts
// with RFC 822 headers (Protected Headers), strip them and decode the body's
// Content-Transfer-Encoding.
func stripMIMEHeaders(text string) string {
	body, _ := stripMIMEHeadersAndExtract(text)
	return body
}

// stripMIMEHeadersAndExtract returns the decoded body plus the In-Reply-To
// value from inner Protected Headers (empty string if none).
func stripMIMEHeadersAndExtract(text string) (body, inReplyTo string) {
	body = text
	lines := strings.SplitN(text, "\n", 2)
	if len(lines) < 2 {
		return
	}
	if !isHeaderLine(strings.TrimRight(lines[0], "\r")) {
		return
	}
	sep := strings.Index(text, "\r\n\r\n")
	sepLen := 4
	if sep < 0 {
		sep = strings.Index(text, "\n\n")
		sepLen = 2
	}
	if sep < 0 {
		return
	}
	headerBlock := text[:sep]
	rawBody := text[sep+sepLen:]
	cte, charset, irt := parseHeaderHints(headerBlock)
	inReplyTo = irt
	switch cte {
	case "base64":
		clean := stripWS(rawBody)
		if data, err := base64.StdEncoding.DecodeString(clean); err == nil {
			body = decodeCharset(data, charset)
			return
		}
	case "quoted-printable":
		if data := decodeQP(rawBody); data != nil {
			body = decodeCharset(data, charset)
			return
		}
	}
	body = rawBody
	return
}

func isHeaderLine(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return false
	}
	for i := 0; i < colon; i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func parseHeaderHints(headerBlock string) (cte, charset, inReplyTo string) {
	charset = "utf-8"
	// Unfold continuation lines first.
	var unfolded []string
	for _, raw := range strings.Split(headerBlock, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if (strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")) && len(unfolded) > 0 {
			unfolded[len(unfolded)-1] += " " + strings.TrimSpace(raw)
			continue
		}
		unfolded = append(unfolded, raw)
	}
	for _, line := range unfolded {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		switch name {
		case "content-transfer-encoding":
			cte = strings.ToLower(val)
		case "content-type":
			if i := strings.Index(strings.ToLower(val), "charset="); i >= 0 {
				rest := val[i+len("charset="):]
				rest = strings.TrimPrefix(rest, "\"")
				rest = strings.TrimPrefix(rest, "'")
				end := strings.IndexAny(rest, "\";\t ")
				if end < 0 {
					charset = strings.ToLower(rest)
				} else {
					charset = strings.ToLower(rest[:end])
				}
			}
		case "in-reply-to":
			inReplyTo = strings.Trim(val, "<>")
		}
	}
	return
}

func stripWS(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func decodeQP(s string) []byte {
	collapsed := strings.ReplaceAll(s, "=\r\n", "")
	collapsed = strings.ReplaceAll(collapsed, "=\n", "")
	var out []byte
	for i := 0; i < len(collapsed); i++ {
		c := collapsed[i]
		if c == '=' && i+2 < len(collapsed) {
			h1, h2 := hexVal(collapsed[i+1]), hexVal(collapsed[i+2])
			if h1 >= 0 && h2 >= 0 {
				out = append(out, byte(h1*16+h2))
				i += 2
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

func decodeCharset(data []byte, charset string) string {
	// UTF-8 is the only commonly seen charset for chat-mail; pass through.
	_ = charset
	return string(data)
}

// ── outgoing encryption ───────────────────────────────────────────────────────

// EncryptBodyForPeer returns body encrypted+signed for the recipient if a peer
// public key is available on the relay. Returns the original body if no peer
// key, or any error occurs (caller falls back to sending plaintext).
//
// The plaintext is wrapped in a minimal MIME envelope (Content-Type +
// Chat-Version) so DeltaChat-style clients can decrypt and render it.
func EncryptBodyForPeer(r *Relay, toEmail, body string) string {
	if r.accountEmail == "" {
		return body
	}
	if strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
		return body // already encrypted
	}
	peerKey, err := fetchPeerKey(r, toEmail)
	log.Printf("[pgp] fetchPeerKey(%s): key=%v err=%v", toEmail, peerKey != nil, err)
	if err != nil || peerKey == nil {
		return body
	}
	armoredPriv, err := loadPrivkeyLocal(r.accountEmail)
	if err != nil {
		return body
	}
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPriv))
	if err != nil || len(keyring) == 0 {
		return body
	}
	signer := keyring[0]

	wrapped := "Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"Chat-Version: 1.0\r\n" +
		"\r\n" +
		body

	encrypted, err := pgpSignAndEncrypt([]byte(wrapped), []*openpgp.Entity{peerKey, signer}, signer)
	if err != nil {
		log.Printf("[pgp] encrypt failed for %s: %v", toEmail, err)
		return body
	}
	return encrypted
}

func pgpSignAndEncrypt(plaintext []byte, recipients []*openpgp.Entity, signer *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	cfg := &packet.Config{
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	w, err := openpgp.Encrypt(aw, openpgp.EntityList(recipients), signer, nil, cfg)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	w.Close()
	aw.Close()
	return buf.String(), nil
}

func fetchPeerKey(r *Relay, toEmail string) (*openpgp.Entity, error) {
	url := pgpEndpoint(r.cfg.URL, "/pgp/peerkey?addr=") + toEmail
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", basicAuthHeader(r.accountEmail, r.cfg.Password))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(b))
	if err != nil || len(entities) == 0 {
		return nil, err
	}
	return entities[0], nil
}

func derivePubkeyFromPriv(armoredPriv string) string {
	entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredPriv))
	if err != nil || len(entities) == 0 {
		return ""
	}
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return ""
	}
	if err := entities[0].Serialize(aw); err != nil {
		return ""
	}
	aw.Close()
	return buf.String()
}
