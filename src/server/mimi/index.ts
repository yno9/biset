/** Production entrypoint for the standalone Phase 0 biset-mimi hub. */
import { serveMimiDeployment } from './deployment.ts'

const databasePath = process.env.MIMI_DATABASE_PATH
if (!databasePath) throw new Error('MIMI_DATABASE_PATH is required')
const mode = deploymentMode(process.env.MIMI_MODE)
const publicBaseUrl = process.env.MIMI_PUBLIC_BASE_URL
// Only ever set true for a deployment dedicated to Self Group traffic --
// see MimiDeploymentOptions.allowExternalJoin's doc comment (deployment.ts).
const allowExternalJoin = process.env.MIMI_ALLOW_EXTERNAL_JOIN === 'true'

const port = envInteger('PORT', 8793, 1, 65_535)
const deployment = await serveMimiDeployment({ databasePath, mode, port, publicBaseUrl, allowExternalJoin })
console.info(`biset-mimi (${mode}${allowExternalJoin ? ', external join enabled' : ''}) listening on :${port}`)

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void deployment.server.stop(true).finally(() => {
      deployment.close()
      process.exit(0)
    })
  })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  return value
}

function deploymentMode(value: string | undefined): 'normal' | 'anon' {
  if (value === 'normal' || value === 'anon') return value
  throw new TypeError('MIMI_MODE must be normal or anon')
}
