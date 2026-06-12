package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"golang.org/x/crypto/hkdf"
)

var dkimKey *rsa.PrivateKey

func loadDKIMKey() {
	keyPEM := os.Getenv("BISET_KEY_PEM")
	if keyPEM == "" {
		return
	}
	k, err := deriveDKIMKey(keyPEM)
	if err != nil {
		return
	}
	dkimKey = k
}

func deriveDKIMKey(rsaKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(rsaKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(raw)
	if err != nil {
		return nil, err
	}
	reader := hkdf.New(sha256.New, der, []byte("biset-dkim-rsa-2048"), nil)
	return rsa.GenerateKey(reader, 2048)
}

// signDKIM adds a DKIM-Signature header to a raw RFC 5322 message.
// Returns the original message unchanged if signing is not possible.
func signDKIM(raw []byte, domain, selector string) []byte {
	if dkimKey == nil || domain == "" || selector == "" {
		return raw
	}
	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 dkimKey,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Subject", "Date", "Message-Id", "Content-Type"},
	}
	var out bytes.Buffer
	if err := dkim.Sign(&out, strings.NewReader(string(raw)), opts); err != nil {
		return raw
	}
	return out.Bytes()
}

// DKIMPublicKeyRecord returns the DNS TXT record value for the DKIM public key.
// Publish at: <selector>._domainkey.<domain>  IN TXT  "<value>"
func DKIMPublicKeyRecord() string {
	if dkimKey == nil {
		return ""
	}
	pub, err := x509.MarshalPKIXPublicKey(&dkimKey.PublicKey)
	if err != nil {
		return ""
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
}

// writeDKIMRecordFile writes the DNS TXT record to <dir>/dkim-dns.txt
// so users can retrieve it without watching startup logs.
func writeDKIMRecordFile(dir, selector, domain string) {
	r := DKIMPublicKeyRecord()
	if r == "" || dir == "" {
		return
	}
	content := "# Add this TXT record to DNS:\n" +
		"# " + selector + "._domainkey." + domain + "\n" +
		r + "\n"
	os.WriteFile(filepath.Join(dir, "dkim-dns.txt"), []byte(content), 0644) //nolint:errcheck
}
