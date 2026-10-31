// The picture of someone who has none: a face drawn from their name (Boring Avatars, boringavatars.com, MIT), the same face for the
// same name, in comail's own colours. It fills the round box it is put in.
import Avatar from 'boring-avatars'
import { usePartColors } from './color-settings.ts'

export function GeneratedAvatar({ name, variant = 'beam' }: { name: string; variant?: 'beam' | 'bauhaus' }) {
  const colors = usePartColors('avatar')
  return <span className="avatar-generated" aria-hidden="true"><Avatar name={name || '?'} variant={variant} size="100%" colors={[...colors]} /></span>
}
