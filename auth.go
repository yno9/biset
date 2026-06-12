package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/hkdf"
)

// loadOrGenerateKey reads an RSA private key PEM from path, or generates and
// persists a new 2048-bit key if the file doesn't exist.
func loadOrGenerateKey(path string) string {
	if b, err := os.ReadFile(path); err == nil {
		return string(b)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("keygen: %v", err)
		return ""
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		log.Printf("keygen: %v", err)
		return ""
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		log.Printf("keygen write: %v", err)
	}
	return string(pemBytes)
}

// derivePGPEntity derives a deterministic RSA-3072 OpenPGP entity from the
// biset master RSA private key via HKDF. Same input always produces the same
// OpenPGP key — no separate PGP key file needed.
func derivePGPEntity(rsaKeyPEM string) (*openpgp.Entity, error) {
	block, _ := pem.Decode([]byte(rsaKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	reader := hkdf.New(sha256.New, der, []byte("biset-pgp-rsa-3072"), nil)
	fixedTime := time.Unix(0, 0).UTC()
	cfg := &packet.Config{
		DefaultHash: crypto.SHA256,
		Algorithm:   packet.PubKeyAlgoRSA,
		RSABits:     3072,
		Rand:        reader,
		Time:        func() time.Time { return fixedTime },
	}
	return openpgp.NewEntity("biset", "", "", cfg)
}

// pgpPublicKeyBytes returns raw (non-armored) OpenPGP public key packets,
// used for WKD responses.
func pgpPublicKeyBytes(entity *openpgp.Entity) []byte {
	var buf bytes.Buffer
	if err := entity.Serialize(&buf); err != nil {
		return nil
	}
	return buf.Bytes()
}

// loadPGPKey derives an armored OpenPGP private key from the master RSA key
// PEM, used for WKD key serving.
func loadPGPKey(rsaKeyPEM string) string {
	if rsaKeyPEM == "" {
		return ""
	}
	entity, err := derivePGPEntity(rsaKeyPEM)
	if err != nil {
		log.Printf("pgp derive: %v", err)
		return ""
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		return ""
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		return ""
	}
	w.Close()
	return buf.String()
}
