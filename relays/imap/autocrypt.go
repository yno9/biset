package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
)

// savePeerKey stores a peer's raw OpenPGP public key and prefer-encrypt value.
func savePeerKey(vaultDir, addr, keydata, preferEncrypt string) {
	if vaultDir == "" || addr == "" || keydata == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(keydata)
	if err != nil {
		return
	}
	dir := filepath.Join(vaultDir, ".autocrypt")
	os.MkdirAll(dir, 0700) //nolint:errcheck
	base := filepath.Join(dir, strings.ToLower(addr))
	os.WriteFile(base+".pgp", raw, 0600)                    //nolint:errcheck
	os.WriteFile(base+".prefer", []byte(preferEncrypt), 0600) //nolint:errcheck
}

// parseAutocryptHeader parses the value of an Autocrypt: header.
func parseAutocryptHeader(h string) (addr, keydata, preferEncrypt string) {
	preferEncrypt = "nopreference"
	for _, part := range strings.Split(h, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(strings.ToLower(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "addr":
			addr = v
		case "keydata":
			keydata = strings.Map(func(r rune) rune {
				if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
					return -1
				}
				return r
			}, v)
		case "prefer-encrypt":
			preferEncrypt = v
		}
	}
	return
}

// processAutocrypt extracts the Autocrypt header from raw message bytes and
// saves the peer key if the addr matches fromAddr.
func processAutocrypt(vaultDir, fromAddr string, raw []byte) {
	if vaultDir == "" {
		return
	}
	// Find Autocrypt: header in raw message
	lines := bytes.Split(raw, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			break // end of headers
		}
		s := string(line)
		if !strings.HasPrefix(strings.ToLower(s), "autocrypt:") {
			continue
		}
		val := strings.TrimSpace(s[len("autocrypt:"):])
		addr, keydata, prefer := parseAutocryptHeader(val)
		if addr == "" || keydata == "" {
			continue
		}
		if !strings.EqualFold(addr, fromAddr) {
			continue
		}
		savePeerKey(vaultDir, addr, keydata, prefer)
		return
	}
}
