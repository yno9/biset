// did:web identifier construction and the DID-to-HTTPS transform
// (did:web method spec, "Read (Resolve)"). Subdomain-only on purpose: this
// identity layer names one subdomain per identity (`y.biset.md`, not
// `biset.md:y`) so a did:web mirror sits at the ordinary root path Bluesky's
// atproto did:web handling expects (`https://y.biset.md/.well-known/did.json`)
// — see PLAN.md's identity-generation scope decision on subdomain vs. path
// form. No path-segment form: add it if a real caller needs one.
export function buildWebDid(domain: string): string {
  return `did:web:${domain}`
}

export function didWebToHttpsUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error('didWebToHttpsUrl: not a did:web identifier')
  const domainAndPort = did.slice('did:web:'.length)
  if (!domainAndPort) throw new Error('didWebToHttpsUrl: missing domain segment')

  let domain = domainAndPort
  let port: number | undefined
  const portMatch = /^(.+)%3A(\d{1,5})$/i.exec(domainAndPort)
  if (portMatch) {
    domain = portMatch[1]!
    port = Number(portMatch[2])
  }
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname
  return `https://${hostPart}/.well-known/did.json`
}
