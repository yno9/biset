// A React screen mounted into a node of the page's own markup (index.html): the rest of the page is
// still plain DOM while screens move over one at a time.
import type { ReactNode } from 'react'
import { flushSync } from 'react-dom'
import { createRoot } from 'react-dom/client'

export function mountIsland(containerId: string, screen: ReactNode): void {
  const container = document.getElementById(containerId)
  if (!container) throw new Error(`#${containerId} is not in the page`)
  // Synchronous, so plain DOM code that goes looking for the screen's nodes right after finds them.
  flushSync(() => createRoot(container).render(screen))
}
