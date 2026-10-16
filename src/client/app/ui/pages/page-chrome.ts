import { useLayoutEffect } from 'react'

/** What every page other than the thread does to the shell around it while it is on screen: marks
 * #app as showing a menu page (CSS hides the thread-only controls on it), titles the header, and
 * clears what belongs to a thread (past rows, the group icon, the conversation strip, the reply
 * dock). Undone when the page goes away. */
export function usePageChrome(title: 'account' | 'config' | 'compose'): void {
  useLayoutEffect(() => {
    const app = document.getElementById('app')
    app?.setAttribute('data-menu-page', `/${title}`)
    const past = document.getElementById('past-threads')
    if (past) past.innerHTML = ''
    const headerTitle = document.getElementById('header-thread-title')
    if (headerTitle) { headerTitle.textContent = title; headerTitle.className = '' }
    const groupIcon = document.getElementById('header-group-icon')
    if (groupIcon) groupIcon.style.display = 'none'
    const convMeta = document.getElementById('conv-meta')
    if (convMeta) convMeta.style.display = 'none'
    // A reply box left over from whichever thread was open before is parked in #reply-dock
    // (position:fixed): nothing else clears it just because another page is on screen.
    const dock = document.getElementById('reply-dock')
    if (dock) dock.innerHTML = ''
    return () => {
      app?.removeAttribute('data-menu-page')
      const meta = document.getElementById('conv-meta')
      if (meta) meta.style.display = ''
    }
  }, [title])
}
