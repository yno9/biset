// The picture of someone who has none: a face drawn from their name (Boring Avatars, boringavatars.com, MIT), the same face for the
// same name, in biset's own colours. It fills the round box it is put in.
import Avatar from 'boring-avatars'
import { AVATAR_COLORS } from './format.ts'

export function GeneratedAvatar({ name }: { name: string }) {
  return <span className="avatar-generated" aria-hidden="true"><Avatar name={name || '?'} variant="beam" size="100%" colors={[...AVATAR_COLORS]} /></span>
}
