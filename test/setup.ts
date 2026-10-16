// Matchers the suite took from bun:test and vitest does not have.
import { expect } from 'vitest'

expect.extend({
  toStartWith(received: string, prefix: string) {
    return { pass: typeof received === 'string' && received.startsWith(prefix), message: () => `expected ${JSON.stringify(received)} ${this.isNot ? 'not ' : ''}to start with ${JSON.stringify(prefix)}` }
  },
  toBeTrue(received: unknown) {
    return { pass: received === true, message: () => `expected ${String(received)} ${this.isNot ? 'not ' : ''}to be true` }
  },
  toBeFalse(received: unknown) {
    return { pass: received === false, message: () => `expected ${String(received)} ${this.isNot ? 'not ' : ''}to be false` }
  },
})

declare module 'vitest' {
  interface Assertion<T> {
    toStartWith(prefix: string): T
    toBeTrue(): T
    toBeFalse(): T
  }
}
