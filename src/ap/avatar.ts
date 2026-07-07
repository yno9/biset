// ── ActivityPub actor avatars ────────────────────────────────────────────────
//
// Fediverse actors advertise a profile picture in their actor document's `icon`
// field. AP knowledge is isolated here (mirroring src/deltachat/): the generic
// avatar cache (src/deltachat/avatar.ts) stores the resolved image so the UI
// stays protocol-agnostic — it just reads avatarDataUrl(addr).
//
// Two directions:
//   - learnApAvatar   : fetch a remote actor's icon (via the AP relay's /resolve)
//                       and cache it for display.
//   - advertise*      : upload our own avatar to the AP relay so it appears in
//                       our actor document for remote servers (Mastodon et al.).

import { avatarDataUrl, saveAvatar } from '../deltachat/avatar.ts'
import { sessions, relaysFor, isApRelay } from '../context.ts'

const trim = (u: string) => u.replace(/\/$/, '')

// Resolve a fediverse handle's profile picture via the AP relay's /resolve
// (server-side webfinger + actor fetch → icon URL) and cache it under the handle.
// The icon is kept as a remote URL — used directly as an <img src>, so no
// cross-origin fetch/decoding is needed. No-op when already known.
export async function learnApAvatar(handle: string, apUrl: string): Promise<void> {
  if (!handle || !apUrl) return
  if (avatarDataUrl(handle)) return
  try {
    const r = await fetch(`${trim(apUrl)}/resolve?acct=${encodeURIComponent(handle)}`)
    if (!r.ok) return
    const j = await r.json() as { icon?: string }
    if (j?.icon) await saveAvatar(handle, j.icon)
  } catch { /* discovery is best-effort */ }
}

// Upload our own avatar image to one AP relay so its actor document advertises
// it. The stored avatar is a data: URL (set locally); we ship the raw bytes.
export async function advertiseApAvatar(email: string, apUrl: string, authToken: string): Promise<void> {
  const dataUrl = avatarDataUrl(email)
  if (!dataUrl || !apUrl || !dataUrl.startsWith('data:')) return
  const localpart = email.split('@')[0]
  try {
    const blob = await (await fetch(dataUrl)).blob()
    await fetch(`${trim(apUrl)}/${encodeURIComponent(localpart)}/avatar`, {
      method: 'PUT',
      headers: {
        'Authorization': 'Basic ' + btoa(email + ':' + authToken),
        'Content-Type': blob.type || 'image/jpeg',
      },
      body: blob,
    })
  } catch { /* best-effort */ }
}

// Advertise one identity's avatar to every AP relay serving it.
export async function advertiseOwnAvatarForEmail(email: string): Promise<void> {
  for (const s of relaysFor(email)) {
    if (isApRelay(s.account.serverUrl)) {
      await advertiseApAvatar(email, s.account.serverUrl, s.account.password)
    }
  }
}

// Advertise every connected identity's avatar to its AP relay(s). Called once
// after sessions are established.
export async function advertiseAllOwnAvatars(): Promise<void> {
  for (const s of sessions) {
    if (isApRelay(s.account.serverUrl)) {
      await advertiseApAvatar(s.account.email, s.account.serverUrl, s.account.password)
    }
  }
}
