/** Production entrypoint for the standalone Phase 0 biset-mimi hub. */
import { serveMimiDeployment } from './deployment.ts'

const databasePath = Bun.env.MIMI_DATABASE_PATH
if (!databasePath) throw new Error('MIMI_DATABASE_PATH is required')

const port = envInteger('PORT', 8793, 1, 65_535)
const deployment = serveMimiDeployment({ databasePath, port })
console.info(`biset-mimi listening on :${port}`)

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    deployment.server.stop()
    deployment.close()
    process.exit(0)
  })
}

function envInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = Bun.env[name]
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`${name} must be an integer between ${min} and ${max}`)
  return value
}
