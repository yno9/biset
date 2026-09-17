import { readFileSync } from 'node:fs'
import { createMailDkimSigner, type MailDkimSigner } from '../mediator/mail-plugin/dkim.ts'

export function loadMailRelayDkim(
  env: Record<string, string | undefined>,
  readKey: (path: string) => string = path => readFileSync(path, 'utf8'),
): MailDkimSigner | undefined {
  const domainName = env.MAIL_RELAY_DKIM_DOMAIN?.trim()
  const keySelector = env.MAIL_RELAY_DKIM_SELECTOR?.trim()
  const keyPath = env.MAIL_RELAY_DKIM_PRIVATE_KEY_PATH?.trim()
  if (!domainName && !keySelector && !keyPath) return undefined
  if (!domainName || !keySelector || !keyPath) throw new Error('MAIL_RELAY_DKIM_DOMAIN, MAIL_RELAY_DKIM_SELECTOR and MAIL_RELAY_DKIM_PRIVATE_KEY_PATH must be configured together')
  if (keyPath === env.MAIL_RELAY_TLS_KEY_PATH?.trim()) throw new Error('DKIM must not reuse the TLS private key')
  return createMailDkimSigner({ domainName, keySelector, privateKey: readKey(keyPath) })
}
