# Test fixtures

`smtp-tls-cert.pem`/`smtp-tls-key.pem` are copied verbatim from
`jmapsmtp.bak/xtask/fixtures/` (the archived Rust relay's own test fixtures).
Self-signed for the reserved domain `mail.example.com` (RFC 2606), committed
on purpose — see that directory's own README.md for the full rationale
(short version: opportunistic inbound STARTTLS is unauthenticated regardless,
so there is no reuse risk). Used by `test/core/adapters/mail-smtp-listener.test.ts`'s
STARTTLS integration test.
