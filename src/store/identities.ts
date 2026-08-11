import type { Identity } from 'jmap-rfc-types'

let store: Identity[] = []

export function all(): Identity[] {
  return store
}

export function set(list: Identity[]): void {
  store = list
}
