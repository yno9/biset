import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import {
  buildActorSequencer,
  buildLocalJmapReadModel,
  buildMailSubmitter,
  buildVaultCryptoBoundary,
  mailFromForIdentity,
  maintainSelfGroup,
} from './identity/bootstrap.ts'
import { IndexedDbMlsSelfGroupStore } from './mls/store.ts'
import { IndexedDbMlsKeyPackageStore } from './mls/keypackage-store.ts'
import { IndexedDbVaultStore } from './vault/store.ts'
import { setupNewUserPage } from './ui/account-create.ts'
import { refreshInbox, showApp, showSysMsg } from './ui/shell.ts'
import { configureCompose } from './ui/thread.ts'
import type { ReplySendInput } from './ui/thread.ts'
import { configureAccountPage } from './ui/account-page.ts'
import { configureComposePage } from './ui/compose-page.ts'
import { readBisetConfig } from './ui/config.ts'
import { VaultBackedLocalJmapMutationSink } from './local-jmap/vault-mutation-sink.ts'
import type { LocalJmapMutationSink } from './local-jmap/gateway.ts'
import { LocalJmapGateway, LocalJmapTransport } from './local-jmap/gateway.ts'
import { buildOutboundRfc5322 } from './mail/rfc5322-builder.ts'

/**
 * New-client bootstrap. The only branch this makes is "does this device
 * already have an identity locally": with none, it shows the new-user page
 * (ui/account-create.ts, identity/bootstrap.ts's createNewIdentity). With
 * one, it opens the vault UI (read model + reply-send, PLAN.md §7) against
 * the first local identity's vault, and still runs `maintainSelfGroup` for
 * every local identity (self-group catch-up + roster reflection + KeyPackage
 * pool top-up) so a second identity on this device doesn't silently drift
 * out of sync just because there's no account switcher yet.
 */
export async function bootClient(): Promise<void> {
  const newUserPage = document.getElementById('new-user-page')

  const records = await new IndexedDbIdentityRecordStore().list().catch(() => [])
  if (records.length === 0) {
    if (newUserPage) newUserPage.style.display = 'flex'
    setupNewUserPage()
    return
  }

  if (newUserPage) newUserPage.style.display = 'none'

  const selfGroupStore = new IndexedDbMlsSelfGroupStore()
  const vaultStore = await IndexedDbVaultStore.open()
  // Single-account slice: the vault UI reads/writes the first local
  // identity's vault. maintainSelfGroup below still runs for every identity
  // on this device, so a second one doesn't silently drift out of sync just
  // because there's no account switcher yet (PLAN.md §7 plan, out of scope).
  const identity = records[0]!
  const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, identity.did)
  configureAccountPage({ did: identity.did })

  const { apexDomain, coreBaseUrl } = readBisetConfig()
  // Reply-send needs the same signing/MLS boundary maintainSelfGroup already
  // requires a deviceKid for -- with neither a core to submit through nor a
  // device identity to sign with, the UI stays read-only, matching how this
  // file has always treated a missing coreBaseUrl.
  if (coreBaseUrl && apexDomain && identity.deviceKid) {
    const boundary = buildVaultCryptoBoundary(vaultStore, vaultStore, selfGroupStore, identity)
    const sequencer = await buildActorSequencer(vaultStore, identity.did, identity.deviceKid)
    const mutationSink = new VaultBackedLocalJmapMutationSink({
      accountId: `biset:${identity.did}`,
      identityId: identity.did,
      actorDeviceId: identity.deviceKid,
      nextActorSeq: () => sequencer.nextActorSeq(),
      initialParents: () => sequencer.initialParents(),
      activeSegment: () => boundary.activeSegment(),
      signer: boundary.signer,
      committer: vaultStore,
    })
    const submitter = buildMailSubmitter(vaultStore, selfGroupStore, identity, mutationSink, apexDomain, coreBaseUrl)
    const localMutationSink: LocalJmapMutationSink = {
      emailSet: (arguments_, snapshot) => mutationSink.emailSet(arguments_, snapshot),
      submitMail: (arguments_, snapshot) => submitter.submitMail(arguments_, snapshot),
    }
    const transport = new LocalJmapTransport(new LocalJmapGateway({
      accountId: `biset:${identity.did}`,
      identityId: identity.did,
      readModel,
      mutationSink: localMutationSink,
    }))
    const mailFrom = mailFromForIdentity(identity.did, apexDomain)

    const sendReply = async (input: ReplySendInput): Promise<void> => {
      const { rawRfc5322 } = buildOutboundRfc5322({
        from: mailFrom,
        to: input.toAddrs,
        subject: input.subject,
        body: input.body,
        inReplyTo: input.inReplyTo,
        references: input.references,
      })
      const emailId = crypto.randomUUID()
      const now = new Date().toISOString()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: emailId,
          threadId: crypto.randomUUID(),
          mailboxIds: { outbox: true },
          keywords: {},
          receivedAt: now,
          sentAt: now,
          from: [{ email: mailFrom }],
          to: input.toAddrs.map(email => ({ email })),
          subject: input.subject,
        },
        rawRfc5322,
      }, snapshot)
      await transport.call([{ name: 'EmailSubmission/set', callId: 's1', arguments: { create: { s1: { emailId } } } }])
      await refreshInbox(readModel)
    }

    configureCompose({
      selfAddress: mailFrom,
      sendReply,
      onError: message => {
        showSysMsg(message)
        console.warn('[sendReply]', message)
      },
    })
    // Same commit-then-submit function as reply -- buildOutboundRfc5322
    // treats a missing inReplyTo/references as a fresh thread, so nothing
    // new-message-specific is needed here.
    configureComposePage({
      selfAddress: mailFrom,
      sendMessage: sendReply,
      onError: message => {
        showSysMsg(message)
        console.warn('[sendMessage]', message)
      },
    })
  }

  showApp()
  await refreshInbox(readModel).catch(e => {
    showSysMsg('Could not load the inbox')
    console.warn('[refreshInbox]', e instanceof Error ? e.message : e)
  })

  if (!coreBaseUrl) return
  const keyStore = new IndexedDbMlsKeyPackageStore()
  for (const record of records) {
    await maintainSelfGroup(selfGroupStore, keyStore, record, { coreBaseUrl, wraps: vaultStore, segments: vaultStore }).catch(e => {
      console.warn(`[maintainSelfGroup] ${record.did}:`, e instanceof Error ? e.message : e)
    })
  }
}

/** Keeps the initial public API explicit while account routing is implemented. */
export function accountKind(session: AccountSession): AccountSession['kind'] {
  return session.kind
}

bootClient()
