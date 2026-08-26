// Wires mail/openpgp-credential.ts's pure key-generation helpers to a real
// identity: mints this identity's OpenPGP credential once (if it doesn't
// have one yet), stores the private key in the vault
// (vault/openpgp-credential-sink.ts -- synced to every one of this
// identity's own trusted devices, the shared-secret-across-devices shape
// PGP's single-key-per-address model requires, unlike DIDComm's per-device
// keys -- see webvh-routing.ts's own note on RoutingDoc.openpgpPublicKey),
// and publishes the public half into routing.json so any other identity
// resolving this DID can encrypt mail to it.
//
// Idempotent (no-ops once a current credential is already published) and
// meant to be called best-effort from main.ts, the same way enableDidComm
// is -- a failure here must never block mail's own already-working
// unencrypted path.
import { generateOpenPgpPrivateCredential, publishableOpenPgpPublicKey } from './openpgp-credential.ts'
import type { OpenPgpCredentialReader } from '../vault/openpgp-credential-reader.ts'
import type { OpenPgpCredentialVaultSink } from '../vault/openpgp-credential-sink.ts'
import type { OpenPgpPrivateCredentialV1 } from '../vault/openpgp-credential.ts'
import { fetchRouting, putRouting, type RoutingOpenPgpKey } from '../didcomm/webvh-routing.ts'
import type { IdentityId } from '../protocol/ids.ts'

export interface EnableOpenPgpMailOptions {
  identityId: IdentityId
  mailAddress: string
  fetch?: typeof fetch
}

export async function enableOpenPgpMail(
  reader: OpenPgpCredentialReader,
  sink: OpenPgpCredentialVaultSink,
  signing: { updateKey: string; privateKey: Uint8Array },
  opts: EnableOpenPgpMailOptions,
): Promise<void> {
  const fetchImpl = opts.fetch ?? fetch
  let credential: OpenPgpPrivateCredentialV1
  try {
    credential = await reader.readCurrent()
  } catch (e) {
    // Only a missing credential is this function's job to fix -- an
    // ambiguous rotation (two independently introduced, unsuperseded keys)
    // is a real conflict that needs an explicit decision, not something to
    // paper over by minting a third competing key.
    if (!(e instanceof Error) || e.message !== 'no OpenPGP credential is available') throw e
    credential = await generateOpenPgpPrivateCredential({
      identityId: opts.identityId,
      userIDs: [{ email: opts.mailAddress }],
      createdAt: new Date().toISOString(),
    })
    await sink.store(credential)
  }

  const publication = await publishableOpenPgpPublicKey(credential)
  const current = await fetchRouting(opts.identityId, fetchImpl)
  if (current?.openpgpPublicKey?.fingerprint === publication.fingerprint) return

  const openpgpPublicKey: RoutingOpenPgpKey = {
    fingerprint: publication.fingerprint,
    armoredPublicKey: publication.armoredPublicKey,
    createdAt: publication.createdAt,
    ...(publication.supersedesFingerprint ? { supersedesFingerprint: publication.supersedesFingerprint } : {}),
  }
  await putRouting(opts.identityId, { service: [], ...current, openpgpPublicKey }, signing, fetchImpl)
}
