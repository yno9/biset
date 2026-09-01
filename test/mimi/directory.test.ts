import { describe, expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { createMimiProtocolDirectory, MIMI_PROTOCOL_DIRECTORY_PATH } from '../../src/mimi/directory.ts'

describe('MIMI provider directory', () => {
  test('publishes all draft endpoint templates at the configured public HTTPS origin', async () => {
    const expected = createMimiProtocolDirectory('https://mimi.example.test')
    expect(expected.update).toBe('https://mimi.example.test/update/{roomId}')
    expect(() => createMimiProtocolDirectory('http://mimi.example.test')).toThrow('HTTPS')
    const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', publicBaseUrl: 'https://mimi.example.test' })
    const response = await deployment.fetch(new Request(`https://internal.test${MIMI_PROTOCOL_DIRECTORY_PATH}`))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual(expected)
    expect((await deployment.fetch(new Request(`https://internal.test${MIMI_PROTOCOL_DIRECTORY_PATH}`, { method: 'POST' }))).status).toBe(405)
    deployment.close()
  })
})
