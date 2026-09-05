#!/usr/bin/env bun
// Which modules does a production entry point actually reach?
//
// Written for PLAN-simplify (2026-09-05) after finding that
// test/preview-normalisation.test.ts had been guarding src/utils.ts -- a
// copy of ui/format.ts's helpers that no production entry had imported
// since the split. The test passed while the code that ships could regress
// on the exact bug it existed to prevent.
//
// knip does not catch that class of problem: a file imported by a test is
// "used" as far as knip is concerned. This walks the import graph from the
// real entry points instead, and reports what only tests reach.
//
// A file listed under "tests only" is not necessarily dead -- most of them
// are parts built ahead of their wiring (ARC.md calls these "部品実装済み").
// The point is to know which is which, deliberately, rather than
// discovering it during a bug hunt.
//
//   bun run scripts/reachability.mjs [--quiet]
import { readFileSync, existsSync } from 'node:fs'
import { resolve, dirname, relative } from 'node:path'
import { Glob } from 'bun'

const ENTRIES = [
  'src/client/app/main.ts', 'src/client/app/sw.ts',
  'src/server/didcomm-mediator/index.ts', 'src/server/mail-plugin/index.ts',
  'src/server/mimi/index.ts',
]

const importsOf = file => {
  let source
  try { source = readFileSync(file, 'utf8') } catch { return [] }
  return [...source.matchAll(/from\s+['"](\.[^'"]+)['"]/g)]
    .map(match => resolve(dirname(file), match[1]))
}

const reachable = entries => {
  const seen = new Set()
  const stack = entries.map(entry => resolve(entry))
  while (stack.length > 0) {
    const current = stack.pop()
    if (seen.has(current) || !existsSync(current)) continue
    seen.add(current)
    stack.push(...importsOf(current))
  }
  return seen
}

const sources = new Set([...new Glob('src/**/*.ts').scanSync('.')].map(path => resolve(path)))
const live = reachable(ENTRIES)
const unreached = [...sources].filter(file => !live.has(file))

// Test reachability is transitive: a module a test never names directly,
// but pulls in through one it does, is still exercised by that test. Only
// counting direct imports put such a module in the "reached by nothing"
// bucket, which is the one people act on -- so it read as safe to delete
// when it was not (found 2026-09-05: identity/web/mirror.ts, reached
// through create-genesis.ts, whose own coverage is what keeps the did:webvh
// resolver tested).
const guardedByTests = new Map()
for (const testFile of new Glob('test/**/*.test.ts').scanSync('.')) {
  const direct = importsOf(resolve(testFile)).filter(file => sources.has(file))
  const seen = new Set()
  const stack = [...direct]
  while (stack.length > 0) {
    const current = stack.pop()
    if (seen.has(current) || !sources.has(current)) continue
    seen.add(current)
    stack.push(...importsOf(current))
  }
  for (const reached of seen) {
    if (live.has(reached)) continue
    const attributed = direct.includes(reached) ? testFile : `${testFile} (indirect)`
    guardedByTests.set(reached, [...(guardedByTests.get(reached) ?? []), attributed])
  }
}

const isVendor = file => relative('.', file).includes('/vendor/')
const orphans = unreached.filter(file => !guardedByTests.has(file) && !isVendor(file))

const quiet = process.argv.includes('--quiet')
console.log(`reachable from production entries: ${sources.size - unreached.length} / ${sources.size}`)
console.log(`reached only by tests:             ${guardedByTests.size}`)
console.log(`reached by nothing (non-vendor):   ${orphans.length}`)

if (!quiet) {
  if (guardedByTests.size > 0) {
    console.log('\n-- reached only by tests --')
    for (const [file, tests] of [...guardedByTests].sort()) {
      console.log(`  ${relative('.', file)}  <- ${tests.join(', ')}`)
    }
  }
  if (orphans.length > 0) {
    console.log('\n-- reached by nothing --')
    for (const file of orphans.sort()) console.log(`  ${relative('.', file)}`)
  }
}
