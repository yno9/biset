// ── Generic modal (src.bak's own openModal, verbatim) ───────────────────────
export function openModal(title: string, bodyEl: HTMLElement, onClose?: () => void): () => void {
  const overlay = document.createElement('div')
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:10001;display:flex;align-items:center;justify-content:center;padding:16px'
  const box = document.createElement('div')
  box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:20px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.3);max-height:90vh;overflow:auto'
  const header = document.createElement('div')
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:16px'
  const h = document.createElement('h3')
  h.textContent = title
  h.style.cssText = 'margin:0;font-size:16px'
  const close = document.createElement('button')
  close.type = 'button'
  close.textContent = '✕'
  close.style.cssText = 'background:none;border:none;color:var(--text-dim);font-size:20px;cursor:pointer;padding:0 4px'
  const dismiss = () => {
    document.removeEventListener('keydown', onKey)
    onClose?.()
    overlay.remove()
  }
  const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') dismiss() }
  document.addEventListener('keydown', onKey)
  close.addEventListener('click', dismiss)
  overlay.addEventListener('click', ev => { if (ev.target === overlay) dismiss() })
  header.append(h, close)
  box.append(header, bodyEl)
  overlay.appendChild(box)
  document.body.appendChild(overlay)
  return dismiss
}
