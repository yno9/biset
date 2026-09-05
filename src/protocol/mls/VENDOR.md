# Vendored ts-mls

Source: <https://github.com/LukaJCB/ts-mls> at **v1.6.2**, MIT (see `LICENSE`
in this directory — the copyright notice travels with the code).

This is a **fork, not a copy**. It is here rather than as an npm dependency for
two reasons, and both are the kind that make upstream merges impossible rather
than merely inconvenient:

1. **A security fix biset cannot ship without.** Upstream builds a Commit with
   no UpdatePath when it removes exactly one member (`clientState.ts`'s
   `needsUpdatePath`, `Object.values(grouped.remove).length > 1`). RFC 9420
   §12.4 requires a path for *any* Remove or Update proposal, and that path is
   the only thing that makes the new epoch's commit secret unknown to the
   member just removed. Without it the commit secret is a zero buffer, everyone
   derives the same next epoch, and **the removed member keeps reading**.
   Device removal being cryptographic is the main reason biset adopted MLS at
   all (`src/mls/self-group.ts`), so this is not a patch that can wait.

2. **Size.** biset ships as one self-contained HTML file loaded from `file://`.
   Upstream pulls in `@hpke/core`, which is ~687KB minified on its own — more
   than the MLS implementation itself (~136KB) — to support fifteen
   ciphersuites biset does not use. Only
   `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` is needed, and its
   primitives (X25519, HKDF-SHA256, AES-128-GCM) are already in the
   `@noble/*` packages biset bundles for everything else.

## What was changed

Every divergence from upstream is marked in the source with a comment starting
`// biset:` so a future re-sync can find them without a diff against a tag.

- `clientState.ts` — the `needsUpdatePath` fix above.
- `processMessages.ts` — an early return once a member has removed ITSELF (a
  self-removed leaf otherwise walks an ancestor chain out of a tree that no
  longer contains it, and spins), and `senderLeafIndex` on an application
  message. The second is an addition, not a fix: WHO sent a message is the one
  thing MLS proves and no transport header can, and a group of several people
  has to attribute messages to a leaf rather than to a name in the plaintext
  that any member could write.
- Ciphersuites other than the one biset uses, and the WebCrypto ("default")
  crypto provider, are removed along with their `@hpke/*` dependencies.
- HPKE (RFC 9180, base mode) is implemented over `@noble/*` in
  `crypto/implementation/noble/`.
- `updatePath.ts`/`createCommit.ts` — an additive, default-preserving
  `newCredential`/`ownCredentialUpdate` parameter on `createUpdatePath`/
  `createCommit`, letting a committer change its OWN leaf's credential via
  its own UpdatePath in the same commit that would otherwise only rekey it.
  RFC 9420 restricts what a committer's self-authored *proposal* may
  contain (no self Update proposal in one's own commit — `clientState.ts`'s
  `validateProposals`), not what a committer's own path update may carry;
  this is not a new capability, just exposing a hook upstream never needed.
  `mls/group.ts`'s `updateOwnCredential` is the one caller, used by domain
  moves (`identity/webvh/move.ts`) to re-issue a device's MLS credential
  after its did:webvh identity relocates (ARC.md §4.6). Every existing
  caller's behavior is unchanged when the new parameter is omitted.

## Keeping it honest

`test/mls-vectors.test.ts` runs the RFC 9420 test vectors from upstream's own
`test_vectors/` against this tree, and `test/mls-core.test.ts` asserts the
removal property that motivated the fork. A future re-sync is expected to keep
both green; if either fails, the fork is wrong, not the vectors.
