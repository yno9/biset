import { createBisetAnchorDeployment } from './deployment.ts'

const dataDir = Bun.env.ANCHOR_DATA_DIR
if (!dataDir) throw new Error('ANCHOR_DATA_DIR is required')

const port = Number(Bun.env.PORT ?? 8788)
const anchor = createBisetAnchorDeployment({
  dataDir,
  domainHeader: Bun.env.ANCHOR_DOMAIN_HEADER ?? 'x-biset-domain',
})

Bun.serve({ port, fetch: anchor.fetch })
console.info(`biset-anchor listening on :${port}`)
