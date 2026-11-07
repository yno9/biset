// Boot timing (console.info "[boot] ..."): how long each wait before the app shows takes.
const bootStartedAt = performance.now()

export function sinceBoot(): number {
  return Math.round(performance.now() - bootStartedAt)
}

export async function timed<T>(label: string, work: Promise<T>): Promise<T> {
  const startedAt = performance.now()
  try { return await work } finally { console.info(`[boot] ${label} +${Math.round(performance.now() - startedAt)}ms (at ${sinceBoot()}ms)`) }
}
