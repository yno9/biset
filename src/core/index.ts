/**
 * The process composition root. Identity discovery (anchor), bounded delivery
 * (mediation), and external adapters share one initial binary but never a
 * mailbox/history API or a storage policy.
 */
const port = Number(Bun.env.PORT ?? 8787)

Bun.serve({
  port,
  fetch(request) {
    const url = new URL(request.url)
    if (url.pathname === '/healthz') {
      return Response.json({ ok: true, service: 'biset-core', storage: 'bounded-only' })
    }
    return new Response('Not found', { status: 404 })
  },
})

console.info(`biset-core listening on :${port}`)
