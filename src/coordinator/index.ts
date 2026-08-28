import { createOidcVaultCoordinatorDeployment } from './deployment.ts'

const databasePath = Bun.env.DATABASE_PATH
const issuer = Bun.env.OIDC_ISSUER
const audience = Bun.env.OIDC_AUDIENCE
if (!databasePath) throw new Error('DATABASE_PATH is required')
if (!issuer) throw new Error('OIDC_ISSUER is required')
if (!audience) throw new Error('OIDC_AUDIENCE is required')

const coordinator = createOidcVaultCoordinatorDeployment({
  databasePath,
  oidc: { issuer, audience, jwksUri: Bun.env.OIDC_JWKS_URI },
})
const port = Number(Bun.env.PORT ?? 8790)
Bun.serve({ port, fetch: coordinator.fetch })
console.info(`biset-coordinator listening on :${port}`)
