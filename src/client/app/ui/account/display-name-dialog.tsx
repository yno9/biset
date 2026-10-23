// The display name is asked for in the text card (text-card-dialog.tsx): it opens with a new random name, and the button on the right of
// the field makes another. Resolves with the text in the field (empty: the caller makes a random one), or `null` when closed.
import { randomDisplayName } from './default-name.ts'
import { requestText } from './text-card-dialog.tsx'

export function requestDisplayName(): Promise<string | null> {
  return requestText({
    title: 'Display name', value: randomDisplayName(), hint: 'Shown to the people you write to.',
    reload: { label: 'New random name', next: randomDisplayName },
  })
}
