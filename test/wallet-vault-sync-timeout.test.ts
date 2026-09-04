// Regression coverage for the did.md Wallet Vault sync's busy flag
// (main.ts's synchronizeWalletVault / syncBusy).
//
// MimiClientTransport has no timeout of its own, so a hung fetch inside a
// round of sync never settles. With `syncBusy` set and no timeout to lose
// the race to, the flag stays true forever, every later trigger's
// `if (syncBusy) return` silently no-ops, and the account simply stops
// receiving anything -- with nothing logged. That exact failure was found
// live on the local-identity path on 2026-09-02 (see runMimiSync's own
// comment); the Wallet path carried the same busy flag with none of the
// protection.
//
// This is a SOURCE-level contract test, deliberately: src/main.ts is the
// browser entry point (it calls bootClient() at import time and pulls in
// DOM-dependent UI modules), so there is no seam to import
// synchronizeWalletVault through and no way to drive it from bun:test.
// Asserting the shape of the code is the only available regression barrier
// -- it is worth having, because the bug is precisely a MISSING guard that
// nothing else would notice.
import { describe, expect, test } from 'bun:test'

const source = await Bun.file(new URL('../src/main.ts', import.meta.url)).text()

/** The `configureWalletAccountIfPresent` body -- the whole Wallet branch. */
function walletBranch(): string {
  const start = source.indexOf('async function configureWalletAccountIfPresent')
  expect(start).toBeGreaterThan(-1)
  const end = source.indexOf('export async function bootClient', start)
  expect(end).toBeGreaterThan(start)
  return source.slice(start, end)
}

/** One 4-space-indented arrow-function body inside that branch. */
function arrowBody(within: string, declaration: string): string {
  const start = within.indexOf(declaration)
  expect(start).toBeGreaterThan(-1)
  const end = within.indexOf('\n    }\n', start)
  expect(end).toBeGreaterThan(start)
  return within.slice(start, end)
}

describe('did.md Wallet MIMI Vault sync guard (main.ts)', () => {
  const entry = arrowBody(walletBranch(), 'const synchronizeWalletVault = async ()')

  test('the busy flag is set on entry and always cleared in a finally', () => {
    expect(entry).toContain('if (syncBusy) return')
    expect(entry).toContain('syncBusy = true')
    expect(/finally\s*\{[^}]*syncBusy = false/.test(entry)).toBe(true)
  })

  test('the guarded sync is raced against a timeout, so the flag cannot wedge', () => {
    // Without this race a hung transport keeps `syncBusy` true forever and
    // the finally above never runs.
    expect(entry).toContain('Promise.race([')
    const timeout = /setTimeout\(\(\) => reject\([^)]*\)\), *([\d_]+)\)/.exec(entry)
    expect(timeout).not.toBeNull()
    const budgetMs = Number(timeout![1]!.replace(/_/g, ''))
    expect(budgetMs).toBeGreaterThan(0)
    // Same budget the local-identity path settled on -- long enough that a
    // slow-but-live sync is never cut short, short enough that a wedged one
    // recovers within one user-visible beat.
    expect(budgetMs).toBe(25_000)
  })

  test('a lost race still reports, instead of becoming an unhandled rejection', () => {
    expect(/catch \(error\)[\s\S]{0,400}state: 'error'/.test(entry)).toBe(true)
    expect(entry).toContain("console.warn('[did.md Wallet MIMI Vault sync]'")
  })
})
