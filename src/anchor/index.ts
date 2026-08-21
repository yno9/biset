/**
 * The future anchor owns discovery and bounded protocol buffers only.  It must
 * not expose JMAP history, search, or mailbox APIs.
 */
const port = Number(Bun.env.PORT ?? 8787)

Bun.serve({
  port,
  fetch(request) {
    const url = new URL(request.url)
    if (url.pathname === '/healthz') {
      return Response.json({ ok: true, service: 'biset-anchor', storage: 'bounded-only' })
    }
    return new Response('Not found', { status: 404 })
  },
})

console.info(`biset-anchor listening on :${port}`)
