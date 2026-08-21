import { createBisetCoreFetchHandler } from './app.ts'

/**
 * The default binary deliberately exposes health only. A deployment must
 * inject an identity/MLS-authorised delivery store through `app.ts` before it
 * can expose bounded relay endpoints.
 */
const port = Number(Bun.env.PORT ?? 8787)
const fetch = createBisetCoreFetchHandler({})

Bun.serve({
  port,
  fetch,
})

console.info(`biset-core listening on :${port}`)
