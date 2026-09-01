import { describe, expect, test } from 'bun:test'
import { MimiRouteSelectionError, selectMimiRoomRoute } from '../../src/mls/mimi-client-routing.ts'

const endpoints = { normalBaseUrl: 'https://normal.example/mimi/', anonBaseUrl: 'https://anon.example/mimi/' }
const anonymousPeer = { peerId: 'did:example:alice', discoveryVerified: true, supportsNormal: true, anonymousMmrVersion: 1 as const }

describe('MIMI client routing', () => {
  test('uses anon only when every verified participant supports anonymous MMR v1', () => {
    expect(selectMimiRoomRoute('prefer-anon', endpoints, [anonymousPeer, { ...anonymousPeer, peerId: 'did:example:bob' }])).toEqual({ mode: 'anon', baseUrl: 'https://anon.example/mimi' })
  })

  test('falls back from an optional anonymous preference only to mutually supported normal mode', () => {
    expect(selectMimiRoomRoute('prefer-anon', endpoints, [{ peerId: 'did:example:bob', discoveryVerified: true, supportsNormal: true }])).toEqual({ mode: 'normal', baseUrl: 'https://normal.example/mimi' })
    expect(() => selectMimiRoomRoute('prefer-anon', endpoints, [{ peerId: 'did:example:bob', discoveryVerified: true, supportsNormal: false }])).toThrow('normal MIMI mode')
  })

  test('never silently downgrades a required anonymous room', () => {
    expect(() => selectMimiRoomRoute('require-anon', endpoints, [{ peerId: 'did:example:bob', discoveryVerified: true, supportsNormal: true }])).toThrow('anonymous MMR v1')
  })

  test('rejects unverified discovery and unsafe local provider origins', () => {
    expect(() => selectMimiRoomRoute('normal', endpoints, [{ ...anonymousPeer, discoveryVerified: false }])).toThrow(MimiRouteSelectionError)
    expect(() => selectMimiRoomRoute('normal', { ...endpoints, normalBaseUrl: 'http://normal.example' }, [anonymousPeer])).toThrow('HTTPS')
  })
})
