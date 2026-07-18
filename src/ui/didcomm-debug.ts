// Minimal debug UI for verifying biset's DIDComm client code (src/did/peer.ts
// + src/did/document.ts + src/did/didcomm/*) against a real mediator, with a
// human at the wheel. Deliberately NOT integrated with the normal inbox/
// thread UI — the goal right now is verifying the plumbing works, not
// shipping the feature. See PLAN.md's "DIDComm transport identity" (did:peer
// and did:dht direct now coexist) / implementation-progress log.
import { generatePeerIdentity, identityFromKeys, b64url, b64urlDecodeToBytes, type PeerIdentity } from '../did/peer.ts'
import { getDidRecord, storeDidRecord } from '../did/store.ts'
import { buildOwnDocument } from '../did/publish.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, type MediatorInfo } from '../did/didcomm/coordinate.ts'
import { registerDidCommViaDht } from '../did/didcomm/register.ts'
import { sendDidComm } from '../did/didcomm/send.ts'
import { pickupDeliver } from '../did/didcomm/pickup.ts'
import { resolveDidCommDoc, resolveSenderPublicKey } from '../did/didcomm/resolve.ts'
import { PUBLIC_PKARR_FALLBACKS } from '../did/resolver.ts'
import type { DidCommSender } from '../did/didcomm/message.ts'
import { sessions } from '../context.ts'
import { hexToBytes } from '../utils.ts'
import { standaloneDid } from '../did/create-standalone.ts'
import { buildBisetDocument } from '../did/document.ts'

const PEER_KEYS_STORAGE_KEY = 'biset_didcomm_debug_keys'
const MEDIATOR_STORAGE_KEY = 'biset_didcomm_debug_mediator'
const DEFAULT_MEDIATOR_URL = 'http://localhost:4100'

type ActiveIdentity =
  | { kind: 'peer'; own: PeerIdentity; mediator: MediatorInfo }
  | { kind: 'dht'; own: DidCommSender; mediator: MediatorInfo }

let active: ActiveIdentity | null = null

function loadOrCreatePeerKeys(): { xPriv: Uint8Array; edPriv: Uint8Array } {
  const stored = localStorage.getItem(PEER_KEYS_STORAGE_KEY)
  if (stored) {
    const { xPriv, edPriv } = JSON.parse(stored)
    return { xPriv: b64urlDecodeToBytes(xPriv), edPriv: b64urlDecodeToBytes(edPriv) }
  }
  const fresh = generatePeerIdentity()
  localStorage.setItem(PEER_KEYS_STORAGE_KEY, JSON.stringify({ xPriv: b64url(fresh.xPriv), edPriv: b64url(fresh.edPriv) }))
  return { xPriv: fresh.xPriv, edPriv: fresh.edPriv }
}


export function renderDidcommDebugPage(): string {
  return `<div class="cmd-page-content wide-page">
    <div class="cmd-page-section">
      <h3>DIDComm (debug)</h3>
      <p style="font-size:12px;color:var(--text-dim);margin-top:0">See PLAN.md "DIDComm transport identity". Not wired into the normal inbox; for verifying the mediator round-trip directly.</p>
      <label style="display:block;margin-bottom:8px">Identity method<br>
        <select id="dc-method">
          <option value="peer">did:peer (per-contact fallback)</option>
          <option value="dht">did:dht (direct)</option>
        </select>
      </label>
      <label style="display:block;margin-bottom:8px">Mediator URL<br>
        <input id="dc-mediator-url" type="text" placeholder="${DEFAULT_MEDIATOR_URL}" style="width:100%">
      </label>
      <button id="dc-register-btn">Register with mediator</button>
      <div id="dc-my-did" style="font-size:11px;word-break:break-all;margin-top:8px;color:var(--text-dim)">(not registered yet)</div>
    </div>
    <div class="cmd-page-section">
      <h3>Send</h3>
      <label style="display:block;margin-bottom:8px">Recipient DID (did:peer:2... or did:dht:...)<br>
        <input id="dc-to-did" type="text" style="width:100%">
      </label>
      <textarea id="dc-send-body" placeholder="message body" style="width:100%;min-height:60px"></textarea>
      <button id="dc-send-btn">Send</button>
      <div id="dc-send-status" style="font-size:11px;word-break:break-all;margin-top:8px;color:var(--text-dim)"></div>
    </div>
    <div class="cmd-page-section">
      <h3>Inbox</h3>
      <button id="dc-poll-btn">Check for messages</button>
      <pre id="dc-inbox-out" style="white-space:pre-wrap;word-break:break-all;font-size:11px;font-family:ui-monospace,monospace;line-height:1.5;margin-top:8px">(nothing yet)</pre>
    </div>
  </div>`
}

export async function onShowDidcommDebug(): Promise<void> {
  const methodSelect = document.getElementById('dc-method') as HTMLSelectElement | null
  const mediatorInput = document.getElementById('dc-mediator-url') as HTMLInputElement | null
  const myDidOut = document.getElementById('dc-my-did')
  const toDidInput = document.getElementById('dc-to-did') as HTMLInputElement | null
  const sendBodyInput = document.getElementById('dc-send-body') as HTMLTextAreaElement | null
  const sendStatusOut = document.getElementById('dc-send-status')
  const inboxOut = document.getElementById('dc-inbox-out')
  if (!methodSelect || !mediatorInput || !myDidOut || !toDidInput || !sendBodyInput || !sendStatusOut || !inboxOut) return

  mediatorInput.value = localStorage.getItem(MEDIATOR_STORAGE_KEY) ?? DEFAULT_MEDIATOR_URL

  document.getElementById('dc-register-btn')?.addEventListener('click', async () => {
    myDidOut.textContent = 'registering…'
    try {
      const rawMediator = mediatorInput.value.trim() || DEFAULT_MEDIATOR_URL
      // A scheme-less "anchor.biset.md" would be fetched RELATIVE to the page
      // (file://…/anchor.biset.md) — force https so it hits the real host.
      const mediatorUrl = /^https?:\/\//i.test(rawMediator) ? rawMediator : 'https://' + rawMediator
      localStorage.setItem(MEDIATOR_STORAGE_KEY, mediatorUrl)

      if (methodSelect.value === 'dht') {
        // Uses the REAL logged-in account's own did:dht — not a throwaway —
        // per explicit request (2026-07-16): the point is direct messaging
        // on the identity biset already has, not a disposable test one.
        // A logged-in account's DID, or — the whole point of relay-less
        // messaging — the standalone identity's, keyed by its DID.
        const email = sessions[0]?.account.email ?? standaloneDid()
        if (!email) throw new Error('no identity — create one first')
        const record = await getDidRecord(email)
        if (!record) throw new Error(`no local DID record for ${email}`)
        if (!record.didCommPrivateKey || !record.didCommPublicKey) {
          throw new Error('this account has no _k1 key yet — log out and back in once to backfill it (lazy migration), then retry')
        }
        const didCommPrivateKey = hexToBytes(record.didCommPrivateKey)

        // Base document: from LIVE session state when there are relays (publish
        // .ts's own builder, the same one the automatic republish uses), or —
        // for a relay-less identity, where that builder returns null — the
        // record alone: no relays, no address, _k1 only.
        const own = await buildOwnDocument(email)
        const doc = own?.doc ?? buildBisetDocument(record.did, hexToBytes(record.rootPublicKey), [], [])
        const rootPrivateKey = own?.rootPrivateKey ?? hexToBytes(record.rootPrivateKey)
        const gatewayUrls = [...(own?.gateways ?? []), ...PUBLIC_PKARR_FALLBACKS]

        const result = await registerDidCommViaDht(didCommPrivateKey, rootPrivateKey, doc, mediatorUrl, gatewayUrls)

        // Persist the registration so publish.ts's builder keeps carrying it
        // — every app start republishes from the local record, so a mediator
        // that isn't recorded here would be dropped on the next launch.
        record.didCommMediatorUrl = result.mediator.url
        record.didCommRoutingKey = result.mediator.doc.keyAgreement[0]
        await storeDidRecord(record)

        active = { kind: 'dht', own: result.own, mediator: result.mediator }
        myDidOut.textContent = record.did
      } else {
        const mediator = await fetchMediatorInfo(mediatorUrl)
        const mediatorXKid = mediator.doc.keyAgreement[0]
        if (!mediatorXKid) throw new Error('mediator DID doc has no keyAgreement')
        const { xPriv, edPriv } = loadOrCreatePeerKeys()
        const own = identityFromKeys(xPriv, edPriv, { uri: mediator.url, routingKeys: [mediatorXKid] })
        await requestMediation(mediator, own)
        await updateKeylist(mediator, own, own.xKid, 'add')
        active = { kind: 'peer', own, mediator }
        myDidOut.textContent = own.did
      }
    } catch (e) {
      myDidOut.textContent = `error: ${e instanceof Error ? e.message : String(e)}`
    }
  })

  document.getElementById('dc-send-btn')?.addEventListener('click', async () => {
    if (!active) { sendStatusOut.textContent = 'error: register with a mediator first'; return }
    sendStatusOut.textContent = 'sending…'
    try {
      const toDid = toDidInput.value.trim()
      const toDoc = await resolveDidCommDoc(toDid) // did:peer self-decodes; did:dht resolves over Pkarr gateways
      if (!toDoc) throw new Error(`could not resolve recipient ${toDid}`)
      await sendDidComm(active.own, toDid, toDoc, {
        type: 'https://didcomm.org/basicmessage/2.0/message',
        body: { content: sendBodyInput.value },
      })
      sendStatusOut.textContent = 'sent'
    } catch (e) {
      sendStatusOut.textContent = `error: ${e instanceof Error ? e.message : String(e)}`
    }
  })

  document.getElementById('dc-poll-btn')?.addEventListener('click', async () => {
    if (!active) { inboxOut.textContent = 'error: register with a mediator first'; return }
    inboxOut.textContent = 'checking…'
    try {
      const delivered = await pickupDeliver(active.mediator, active.own, resolveSenderPublicKey)
      inboxOut.textContent = delivered.length === 0
        ? '(no messages)'
        : delivered.map(d => `from ${d.senderKid}\n${JSON.stringify(d.plaintext, null, 2)}`).join('\n\n---\n\n')
    } catch (e) {
      inboxOut.textContent = `error: ${e instanceof Error ? e.message : String(e)}`
    }
  })
}
