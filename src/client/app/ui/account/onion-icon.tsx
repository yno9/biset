// An onion (Tor), for the controls that are about it.
export function OnionIcon({ size = 18 }: { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 2.5c0 2-1 3.2-2.2 4.4C6.2 8.6 4 11.6 4 15a8 7.5 0 0 0 16 0c0-3.4-2.2-6.4-5.8-8.1C13 5.7 12 4.5 12 2.5Z" /><path d="M12 7c-2 2-3 5-3 8s1 5 3 6c2-1 3-3 3-6s-1-6-3-8Z" />
    </svg>
  )
}
