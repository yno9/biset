import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // A few live-mode tests wait a fixed few tens of ms for a socket; a full-width pool starves them.
    maxWorkers: 2,
    setupFiles: ['test/setup.ts'],
  },
})
