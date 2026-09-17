# Test fixtures

`smtp-tls-cert.pem`/`smtp-tls-key.pem` are copied verbatim from
`jmapsmtp.bak/xtask/fixtures/` (the archived Rust relay's own test fixtures).
Self-signed for the reserved domain `mail.example.com` (RFC 2606), committed
on purpose — see that directory's own README.md for the full rationale
(short version: opportunistic inbound STARTTLS is unauthenticated regardless,
so there is no reuse risk). Used by `test/core/adapters/mail-smtp-listener.test.ts`'s
STARTTLS integration test.

`dkim-smtp-ca.pem`, `dkim-smtp-cert.pem`, and `dkim-smtp-key.pem` are test-only
fixtures generated with `dkim-smtp-openssl.cnf`. The server certificate has SAN
`mail.example.com` and is signed by the test CA. The CA private key is not
committed. The server private key is deliberately public and must never be used
in production. These support authenticated STARTTLS in
`test/mediator/mail-plugin/dkim.test.ts` without disabling certificate checks.
The older self-signed non-CA fixture above is not a valid CA trust anchor for
this test's Bun TLS client. DKIM signing keys are generated separately in memory.
