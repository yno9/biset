# W3 mail design proposal: did.md Wallet mediator mail capability

Status: proposal only; no implementation is authorized by this document.

## Objective

A Wallet identity must be able to receive and submit Internet mail without
requiring a Biset-owned did:webvh domain, a Biset-held identity seed, or a
browser-held SMTP signing key. The did.md-operated mediator is the mail
authority for its Wallet identities.

## Responsibility split

- did.md mediator assigns and owns the mailbox address for a DID, accepts
  inbound SMTP, applies abuse/rate policy, and signs any required SMTP/DKIM
  material. Biset never derives an address from the DID domain.
- did.md Wallet grants a narrowly scoped, audience-bound capability to the
  Biset browser client. The capability names the mediator origin, DID, Biset
  device JKT, granted address(es), allowed operations, and expiry.
- Biset presents that capability with DPoP on mediator mail submission and
  pickup endpoints. The mediator verifies the Wallet Root proof and device
  binding before accepting either operation.
- Inbound MIME is delivered as the existing `MAIL_BRIDGE_INBOUND` DIDComm
  message to the Wallet's mediator-enrolled DIDComm device. The Biset client
  persists it through its existing Vault ingress path.

## Capability shape

Use a Wallet-signed authorization detail, versioned independently from the
current Biset device enrollment detail:

```
{
  type: "urn:biset:mail-mediator:v1",
  mediatorUrl: "https://mediator.did.md/",
  addresses: ["alice@did.md"],
  operations: ["submit", "pickup"],
  deviceJkt: "…",
  expiresAt: "…"
}
```

The mediator must reject a capability whose DID, device JKT, audience,
operation, mediator URL, or expiry does not match the request. Address
ownership is evaluated by the mediator, never by `mailFromForIdentity`.

## Submission flow

1. Biset creates and durably stores the local message before networking.
2. It POSTs the RFC 5322 bytes plus envelope recipients to the capability's
   `submit` endpoint using DPoP.
3. The mediator validates the capability and sender address, queues/relays
   SMTP itself, and returns an idempotency result keyed by the Biset message
   id.
4. Biset records `transport.result` only after an accepted response; failed
   work remains in the durable outbox.

## Required implementation work after approval

- Specify the capability in did.md and add its issuance/refresh behavior.
- Add mediator endpoints and persistent idempotency/abuse controls.
- Replace the apex-domain restriction in `mailFromForIdentity` with a
  capability-derived address reader.
- Add Wallet mail outbox/ingress wiring and end-to-end capability tests.

## Non-goals

- Biset does not operate an MX or mint SMTP signing keys for Wallet users.
- The capability does not expose did.md controller private material.
- This does not alter DIDComm relationship, group-chat, or MIMI Vault
  authorization.
