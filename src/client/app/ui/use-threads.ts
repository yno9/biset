import { useMemo } from 'react'
import { useStore } from '../react/store.ts'
import { composeConfig } from './reply-box.tsx'
import { mail, shell } from './stores.ts'
import { selfAddressesOf, threadsOf, type SelfAddresses, type Threads } from './thread-model.ts'

/** This identity's own addresses, for telling the counterparty from the reader. */
export function useSelf(): SelfAddresses {
  const config = useStore(composeConfig)
  return useMemo(() => selfAddressesOf(config?.selfAddress, config?.selfDid), [config?.selfAddress, config?.selfDid])
}

/** The messages, grouped into threads and left-list rows, with the open thread resolved. */
export function useThreads(): Threads {
  const { messages } = useStore(mail)
  const { focusedThreadKey } = useStore(shell)
  const self = useSelf()
  return useMemo(() => threadsOf(messages, focusedThreadKey, self), [messages, focusedThreadKey, self])
}
