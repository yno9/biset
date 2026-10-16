// A React screen mounted into a node of the page's own markup (index.html): the rest of the page is
// still plain DOM while screens move over one at a time.
import type { ReactNode } from 'react'
import { createRoot } from 'react-dom/client'

export function mountIsland(containerId: string, screen: ReactNode): void {
  const container = document.getElementById(containerId)
  if (!container) throw new Error(`#${containerId} is not in the page`)
  createRoot(container).render(screen)
}
