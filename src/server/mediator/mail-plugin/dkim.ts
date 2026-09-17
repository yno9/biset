import { createPrivateKey } from 'node:crypto'
import nodemailer from 'nodemailer'
import addressparser from 'nodemailer/lib/addressparser'

interface MailToSign {
  mailFrom: string
  rcptTo: string[]
  rawRfc5322: Uint8Array
}

export type MailDkimSigner = (message: MailToSign) => Promise<Uint8Array>

export function validateEnvelopeAddress(address: string): void {
  // This bridge accepts ASCII dot-atom mailboxes, not SMTPUTF8 or quoted locals.
  if (address.length > 254 || !/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*@[^@]+$/.test(address)) throw new TypeError('invalid SMTP envelope address')
  const [local, domain] = address.split('@')
  if (local!.length > 64 || !validDomain(domain!)) throw new TypeError('invalid SMTP envelope address')
}

export function createMailDkimSigner(options: { domainName: string; keySelector: string; privateKey: string }): MailDkimSigner {
  if (!validDomain(options.domainName) || !validDomain(options.keySelector)) throw new TypeError('invalid DKIM domain or selector')
  const key = createPrivateKey(options.privateKey)
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError('DKIM requires a dedicated RSA private key of at least 2048 bits')
  const domainName = options.domainName.toLowerCase()
  const transport = nodemailer.createTransport({
    streamTransport: true, buffer: true, newline: 'windows',
    disableFileAccess: true, disableUrlAccess: true,
    dkim: { domainName, keySelector: options.keySelector, privateKey: options.privateKey, hashAlgo: 'sha256' },
  })
  return async message => {
    validateEnvelopeAddress(message.mailFrom)
    message.rcptTo.forEach(validateEnvelopeAddress)
    if (message.mailFrom.split('@')[1]!.toLowerCase() !== domainName) throw new TypeError('DKIM domain does not match mailFrom')
    const raw = Buffer.from(message.rawRfc5322)
    const end = raw.indexOf('\r\n\r\n')
    if (end < 0 || end > 64 * 1024) throw new TypeError('invalid RFC5322 header section')
    // SMTP DATA uses CRLF. Reject ambiguous wire input rather than rewrite a
    // caller's MIME body; only the required final CRLF may be appended below.
    for (let i = 0; i < raw.length; i++) {
      if ((raw[i] === 10 && raw[i - 1] !== 13) || (raw[i] === 13 && raw[i + 1] !== 10)) throw new TypeError('RFC5322 requires CRLF line endings')
    }
    const fields: Array<{ name: string; value: string }> = []
    for (const line of raw.subarray(0, end).toString('latin1').split('\r\n')) {
      if (line.length > 998 || /[\x00-\x08\x0b-\x1f\x7f]/.test(line)) throw new TypeError('invalid RFC5322 header')
      if (/^[ \t]/.test(line)) {
        if (!fields.length) throw new TypeError('invalid RFC5322 continuation')
        fields[fields.length - 1]!.value += ` ${line.trim()}`
      } else {
        const match = /^([!-9;-~]+):[ \t]*(.*)$/.exec(line)
        if (!match) throw new TypeError('invalid RFC5322 header')
        fields.push({ name: match[1]!.toLowerCase(), value: match[2]! })
      }
    }
    const from = fields.filter(field => field.name === 'from')
    if (from.length !== 1) throw new TypeError('RFC5322 requires exactly one From header')
    const addresses = addressparser(from[0]!.value)
    const address = addresses[0]
    if (addresses.length !== 1 || !address || !('address' in address) || typeof address.address !== 'string') throw new TypeError('RFC5322 From requires one mailbox')
    validateEnvelopeAddress(address.address)
    if (address.address.toLowerCase() !== message.mailFrom.toLowerCase()) throw new TypeError('RFC5322 From does not match authenticated mailFrom')
    const normalized = raw.subarray(-2).equals(Buffer.from('\r\n')) ? raw : Buffer.concat([raw, Buffer.from('\r\n')])
    const result = await transport.sendMail({ envelope: { from: message.mailFrom, to: message.rcptTo }, raw: normalized })
    if (!Buffer.isBuffer(result.message)) throw new Error('DKIM signer did not return bytes')
    const signed = result.message
    // Nodemailer may emit unsigned output if signing could not produce a
    // field. Never allow an existing caller-provided signature to mask that.
    const added = signed.subarray(0, signed.length - normalized.length).toString('ascii')
    if (!added.startsWith('DKIM-Signature:') || !/\bb=[A-Za-z0-9+/\s]+=*\s*$/m.test(added)
      || !signed.subarray(-normalized.length).equals(normalized)) throw new Error('DKIM signing failed or altered RFC5322 bytes')
    return signed
  }
}

function validDomain(value: string): boolean {
  return value.length > 0 && value.length <= 253 && value.split('.').every(label => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))
}
