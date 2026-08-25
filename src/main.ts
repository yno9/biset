import type { AccountSession } from './local-jmap/transport.ts'
import { IndexedDbIdentityRecordStore } from './identity/record-store.ts'
import {
  buildActorSequencer,
  buildLocalJmapReadModel,
  buildMailSubmitter,
  buildVaultCryptoBoundary,
  enableDidComm,
  fromHex,
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
import { MailIngressProjector } from './mail/ingress-projector.ts'
import { synchronizeMailIngress } from './mail/ingress-workflow.ts'
import { CoreIngressTransport } from './vault/core-ingress-transport.ts'
import { CoreVaultDeliveryTransport } from './vault/core-delivery-transport.ts'
import type { IngressVerifierProjector } from './vault/ingress-ingest.ts'
import { DidCommIngressProjector } from './didcomm/ingress-projector.ts'
import { resolveDidCommSenderKey } from './didcomm/webvh-resolve.ts'
import { sendDidCommMessage } from './didcomm/send-message.ts'
import { didCommThreadId } from './didcomm/basicmessage.ts'

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

  const recordStore = new IndexedDbIdentityRecordStore()
  const records = await recordStore.list().catch(() => [])
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
  // `let`, not `const`: enableDidComm (below) updates the record in place
  // once the user opts in, and every closure that reads it (sendReply,
  // syncMailIngress) has to see the new didCommKid/didCommX25519PrivateKey
  // without needing a page reload.
  let identity = records[0]!
  const readModel = buildLocalJmapReadModel(vaultStore, selfGroupStore, identity.did)

  const { apexDomain, coreBaseUrl } = readBisetConfig()
  let syncMailIngress: (() => Promise<void>) | undefined
  const renderAccountPageConfig = () => {
    configureAccountPage({
      did: identity.did,
      didCommKid: identity.didCommKid,
      onEnableDidComm: coreBaseUrl
        ? async () => {
            identity = await enableDidComm(recordStore, identity, { coreBaseUrl })
            renderAccountPageConfig() // re-wires config.didCommKid so the next renderDidCommStatus() call sees it
          }
        : undefined,
    })
  }
  renderAccountPageConfig()
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

    // A `to` of exactly one DID (not an email address) dispatches over
    // DIDComm instead of mail -- the same "to" field both transports share
    // (thread.ts/compose-page.ts have no separate DID input), branching
    // here rather than in the UI layer. Multiple DIDs at once isn't
    // supported: 1:1 chat only (confirmed with the user, 2026-08-25), and
    // mixing a DID with a real email address in one send has no sane
    // meaning either.
    const sendDidCommChat = async (toDid: string, input: ReplySendInput): Promise<void> => {
      if (!identity.didCommKid || !identity.didCommX25519PrivateKey) {
        throw new Error('Enable DIDComm in account settings before messaging a DID')
      }
      const result = await sendDidCommMessage(toDid, input.body, {
        fromKid: identity.didCommKid,
        x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey),
        ...(input.subject ? { subject: input.subject } : {}),
      })
      if (!result.ok) throw new Error(result.error)
      const now = new Date().toISOString()
      const snapshot = await readModel.snapshot()
      await mutationSink.commitMailMessage({
        email: {
          id: crypto.randomUUID(),
          threadId: didCommThreadId(identity.did, toDid),
          mailboxIds: { sent: true },
          keywords: { '$seen': true },
          receivedAt: now,
          sentAt: now,
          from: [{ email: identity.did }],
          to: [{ email: toDid }],
          ...(input.subject ? { subject: input.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(input.body),
      }, snapshot)
      await refreshInbox(readModel)
    }

    const sendReply = async (input: ReplySendInput): Promise<void> => {
      if (input.toAddrs.length === 1 && input.toAddrs[0]!.startsWith('did:')) {
        await sendDidCommChat(input.toAddrs[0]!, input)
        return
      }
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

    // Pulls any mail the core is holding for this device (SMTP listener ->
    // ingress store -> here), verifies+commits it into the vault as
    // message.add, ACKs it, then flushes the resulting vault-delivery pack
    // for sibling devices. Nothing called this before (2026-08-25, found
    // live: mail arrived at the core and sat in its ingress queue forever,
    // never once pulled by any client) -- reply/compose's send path and
    // maintainSelfGroup's catch-up never touched inbound mail at all.
    //
    // A single pulled batch can hold both protocols at once (the shared
    // IngressStore doesn't separate them) -- dispatched here by
    // envelope.protocol to whichever projector actually understands it,
    // same synchronizeMailIngress/ingestIngress orchestration either way
    // (that "Mail" in the name predates DIDComm and is otherwise
    // protocol-agnostic already, see ingress-ingest.ts's own header).
    syncMailIngress = async () => {
      const mailProjector = new MailIngressProjector({
        identityId: identity.did,
        actorDeviceId: identity.deviceKid!,
        nextActorSeq: () => sequencer.nextActorSeq(),
        initialParents: () => sequencer.initialParents(),
        activeSegment: () => boundary.activeSegment(),
        currentSnapshot: () => readModel.snapshot(),
        signer: boundary.signer,
      })
      const didCommProjector = identity.didCommKid && identity.didCommX25519PrivateKey
        ? new DidCommIngressProjector({
            identityId: identity.did,
            actorDeviceId: identity.deviceKid!,
            selfKeys: { kid: identity.didCommKid, x25519PrivateKey: fromHex(identity.didCommX25519PrivateKey) },
            resolveSenderKey: kid => resolveDidCommSenderKey(kid),
            // TODO(PLAN.md §6.1): always "not yet seen" -- there is no
            // committed-dedupe-id lookup wired to this projector yet. Not a
            // safety gap: message.add's own duplicate-emailId conflict
            // check (local-jmap/reducer.ts) still rejects a resent
            // basicmessage using the identical (senderKid, message id)
            // pair, just louder (a thrown/logged error here rather than a
            // quiet skip) than a real alreadyProcessed would be.
            async alreadyProcessed() { return false },
            nextActorSeq: () => sequencer.nextActorSeq(),
            initialParents: () => sequencer.initialParents(),
            activeSegment: () => boundary.activeSegment(),
            currentSnapshot: () => readModel.snapshot(),
            signer: boundary.signer,
          })
        : undefined
      const projector: IngressVerifierProjector = {
        verifyAndProject: envelope => {
          if (envelope.protocol === 'didcomm' && didCommProjector) return didCommProjector.verifyAndProject(envelope)
          return mailProjector.verifyAndProject(envelope)
        },
      }
      const result = await synchronizeMailIngress({
        identityId: identity.did,
        deviceId: identity.deviceKid!,
        store: vaultStore,
        ingressTransport: new CoreIngressTransport({ baseUrl: coreBaseUrl }),
        deliveryTransport: new CoreVaultDeliveryTransport({ baseUrl: coreBaseUrl }),
        signer: boundary.signer,
        projector,
        committer: vaultStore,
      })
      if (result.ingress.ingestedIngressIds.length > 0) await refreshInbox(readModel)
    }
  }

  showApp()
  await refreshInbox(readModel).catch(e => {
    showSysMsg('Could not load the inbox')
    console.warn('[refreshInbox]', e instanceof Error ? e.message : e)
  })
  await syncMailIngress?.().catch(e => {
    console.warn('[syncMailIngress]', e instanceof Error ? e.message : e)
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
