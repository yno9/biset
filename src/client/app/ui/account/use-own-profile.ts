// This identity's own name and picture, from its card: read when the profile source appears and again whenever they change.
import { useEffect, useState } from 'react'
import { PROFILE_CHANGED, type ProfileConfig } from './profile.ts'

export function useOwnProfile(profile: ProfileConfig | undefined): { name?: string; avatar?: string } {
  const [own, setOwn] = useState<{ name?: string; avatar?: string }>({})
  useEffect(() => {
    if (!profile) return
    let current = true
    const load = () => { void profile.current().then(found => { if (current) setOwn(found) }).catch(() => {}) }
    load()
    window.addEventListener(PROFILE_CHANGED, load)
    return () => { current = false; window.removeEventListener(PROFILE_CHANGED, load) }
  }, [profile])
  return own
}
