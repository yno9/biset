// Public per-user landing for https://<host>/<localpart>/. A visitor who is not
// yet a biset user is taken straight to the account-creation screen (#new) with
// the target's profile shown above the fields ("Create account to chat with …").
// After creation they drop into a chat with the target (pending-DM handoff — see
// account-create.ts).
import { setupNewUserPage, showNewUserPage } from './account-create.ts'

const PENDING_DM_KEY = 'biset_pending_dm'

// The chat target survives the account-creation detour in sessionStorage: the
// landing stashes it before showing #new, and the create-success path reads it to
// open the conversation.
export function setPendingDm(target: string): void {
  try { sessionStorage.setItem(PENDING_DM_KEY, target) } catch { /* private mode */ }
}
export function takePendingDm(): string | null {
  try {
    const v = sessionStorage.getItem(PENDING_DM_KEY)
    if (v) sessionStorage.removeItem(PENDING_DM_KEY)
    return v
  } catch { return null }
}

function e(s: string): string {
  return s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!))
}

// Render the target's profile into the #new page header, then show the account
// creation screen. `target` is a full handle (e.g. y@non.md); profile fields come
// from our own AP relay's /resolve (server-side webfinger, no browser CORS) and
// fall back to the localpart. An avatar image is shown when the actor has one.
export async function showUserLanding(target: string, apUrl: string): Promise<void> {
  const localpart = target.split('@')[0] || target
  let name = localpart, icon = ''
  if (apUrl) {
    try {
      const r = await fetch(`${apUrl}/resolve?acct=${encodeURIComponent(target)}`)
      const j = await r.json()
      if (j?.name) name = String(j.name)
      if (j?.icon) icon = String(j.icon)
    } catch { /* best-effort; localpart fallback */ }
  }

  const initial = (name[0] || '?').toUpperCase()
  const avatar = icon
    ? `<img src="${e(icon)}" alt="" style="width:112px;height:112px;border-radius:50%;object-fit:cover">`
    : `<div style="width:112px;height:112px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:46px;font-weight:600;color:#fff;background:var(--accent,#8b5cf6)">${e(initial)}</div>`

  const pigeonEl = document.getElementById('nu-pigeon')
  if (pigeonEl) pigeonEl.style.display = 'none'

  const header = document.getElementById('nu-chat-header')
  if (header) {
    header.style.fontFamily = `'Recursive', system-ui, sans-serif`
    header.innerHTML = `
      ${avatar}
      <div style="font-size:17px;opacity:.6;margin-top:2px">${e(target)}</div>
      <div style="font-size:26px;font-weight:700;margin-top:32px;color:var(--accent2)">Chat with ${e(name)}?</div>
    `
    header.style.display = 'flex'
  }

  setPendingDm(target)
  setupNewUserPage()
  showNewUserPage()
}
