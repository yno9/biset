import { sessions, loadStoredAccounts, saveStoredAccounts } from '../context.ts'
import { $id } from '../utils.ts'
import { initSession, initPGPForSession, addAccount } from '../app.ts'
import { showApp, startPolling } from './shell.ts'
import { loadLeftInboxes } from './left-pane.ts'

export function hideAccountsPage() {
  const el = document.getElementById('accounts-screen')
  if (el) el.style.display = 'none'
}

export function showAccountsPage() {
  const el = document.getElementById('accounts-screen')
  if (el) el.style.display = 'flex'
}

export function setupAccountsPage() {
  renderAccountList()

  const addBtn = document.getElementById('acc-add-btn')
  const errEl = document.getElementById('acc-error')!
  const backBtn = document.getElementById('acc-back-btn')

  addBtn?.addEventListener('click', async () => {
    const raw = ($id('acc-server') as HTMLInputElement).value.trim().replace(/\/$/, '')
    const server = raw && !/^https?:\/\//i.test(raw) ? 'https://' + raw : raw
    const email = ($id('acc-email') as HTMLInputElement).value.trim()
    const pw = ($id('acc-password') as HTMLInputElement).value

    if (!server) { errEl.textContent = 'Server URL required'; errEl.style.display = 'block'; return }
    if (!email) { errEl.textContent = 'Email required'; errEl.style.display = 'block'; return }
    if (!pw) { errEl.textContent = 'Password required'; errEl.style.display = 'block'; return }

    ;(addBtn as HTMLButtonElement).disabled = true
    addBtn.textContent = 'Connecting…'
    errEl.style.display = 'none'

    const session = await addAccount({ serverUrl: server, email, password: pw })
    if (!session) {
      errEl.textContent = 'Connection failed. Check URL, email and password.'
      errEl.style.display = 'block'
      addBtn.textContent = 'Add'
      ;(addBtn as HTMLButtonElement).disabled = false
      return
    }

    initPGPForSession(session)

    ;($id('acc-server') as HTMLInputElement).value = ''
    ;($id('acc-email') as HTMLInputElement).value = ''
    ;($id('acc-password') as HTMLInputElement).value = ''
    addBtn.textContent = 'Add'
    ;(addBtn as HTMLButtonElement).disabled = false
    renderAccountList()
  })

  backBtn?.addEventListener('click', () => {
    if (!sessions.length) return
    hideAccountsPage()
    showApp()
    startPolling()
    loadLeftInboxes()
  })
}

function renderAccountList() {
  const list = document.getElementById('acc-list')
  if (!list) return
  const accounts = loadStoredAccounts()
  const backBtn = document.getElementById('acc-back-btn')
  if (backBtn) backBtn.style.display = accounts.length > 0 ? '' : 'none'

  if (!accounts.length) { list.textContent = 'No accounts'; return }
  list.textContent = ''
  for (const a of accounts) {
    const row = document.createElement('div')
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-radius:8px;background:var(--msg-bg);margin-bottom:6px'
    const label = document.createElement('span')
    label.style.cssText = 'font-size:14px;color:var(--text)'
    label.textContent = a.email
    const del = document.createElement('button')
    del.style.cssText = 'background:none;border:none;color:var(--text-dim);cursor:pointer;font-size:18px;padding:0 4px'
    del.textContent = '×'
    del.addEventListener('click', () => {
      saveStoredAccounts(loadStoredAccounts().filter(x => x.email !== a.email))
      const idx = sessions.findIndex(s => s.account.email === a.email)
      if (idx >= 0) sessions.splice(idx, 1)
      renderAccountList()
    })
    row.append(label, del)
    list.appendChild(row)
  }
}
