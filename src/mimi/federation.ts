/** JSON boundary and provider-owned hooks for draft §5.7 and §5.8. */
import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'
import type { MimiConsentEntry, MimiIdentifierQueryElement, MimiIdentifierRequest, MimiIdentifierResponse, PublishedKeyPackage } from './protocol-types.ts'
import { decodeFrankWire, encodeFrankWire, MimiWireError } from './wire.ts'
import type { MimiAbuseReport } from './protocol-types.ts'

export interface MimiIdentifierDirectory {
  /**
   * The sole policy decision point for identifier search.  Implementations
   * MUST apply every QueryElement with AND semantics and return profiles only
   * for fields that this user has explicitly made searchable under the
   * provider's policy.  In particular, partialName / wholeProfile must not
   * silently turn a non-queryable account into a directory result.  Return
   * `forbidden`, `unsupportedField`, `ambiguous`, or `notFound` rather than
   * exposing a profile when that policy does not permit a match.
   *
   * `sourceProviderDomain` is supplied only after the HTTP boundary has
   * authenticated the requesting provider with mTLS.  Do not use this hook
   * as a general-purpose local user lookup API.
   */
  query(request: MimiIdentifierRequest, sourceProviderDomain: string): Promise<MimiIdentifierResponse>
}

/** Privacy-preserving default: a deployment is never queryable merely
 * because it enables federation.  Operators must intentionally install a
 * policy-enforcing directory implementation before any identifier can be
 * disclosed (the Xavier/Yolanda/Zach cases in draft §5.8). */
export const noIdentifiers: MimiIdentifierDirectory = {
  async query(): Promise<MimiIdentifierResponse> { return { responseCode: 'notFound', foundProfiles: [] } },
}

export function decodeMimiConsentEntryWire(text: string): MimiConsentEntry {
  const input = object(JSONValue(text), 'ConsentEntry')
  const consentOperation = input.consentOperation
  if (consentOperation !== 'cancel' && consentOperation !== 'request' && consentOperation !== 'grant' && consentOperation !== 'revoke') throw new MimiWireError('ConsentEntry.consentOperation is invalid')
  const packages = input.clientKeyPackages === undefined ? undefined : packageArray(input.clientKeyPackages, 'ConsentEntry.clientKeyPackages')
  if (consentOperation === 'grant' ? packages === undefined : packages !== undefined) throw new MimiWireError('only a consent grant may include clientKeyPackages')
  return { consentOperation, requesterUri: string(input.requesterUri, 'ConsentEntry.requesterUri'), targetUri: string(input.targetUri, 'ConsentEntry.targetUri'), roomId: optionalString(input.roomId, 'ConsentEntry.roomId'), clientKeyPackages: packages }
}

export function encodeMimiConsentEntryWire(value: MimiConsentEntry): string {
  return JSON.stringify({ consentOperation: value.consentOperation, requesterUri: value.requesterUri, targetUri: value.targetUri, ...(value.roomId === undefined ? {} : { roomId: value.roomId }), ...(value.clientKeyPackages === undefined ? {} : { clientKeyPackages: value.clientKeyPackages.map(packageJson) }) })
}

export function decodeMimiIdentifierRequestWire(text: string): MimiIdentifierRequest {
  const input = object(JSONValue(text), 'IdentifierRequest')
  if (!Array.isArray(input.queryElements) || input.queryElements.length === 0) throw new MimiWireError('IdentifierRequest.queryElements must be a non-empty array')
  return { queryElements: input.queryElements.map((entry, index) => queryElement(entry, `IdentifierRequest.queryElements[${index}]`)) }
}

export function encodeMimiIdentifierResponseWire(value: MimiIdentifierResponse): string {
  return JSON.stringify({ responseCode: value.responseCode, foundProfiles: value.foundProfiles.map(profile => ({ stableUri: profile.stableUri, fields: profile.fields })) })
}

export function decodeMimiAbuseReportWire(wire: string): MimiAbuseReport {
  const input = object(JSONValue(wire), 'AbuseReport')
  if (!Array.isArray(input.messages) || input.messages.length > 32) throw new MimiWireError('AbuseReport.messages must be an array of at most 32 entries')
  return { reportingUser: optionalString(input.reportingUser, 'AbuseReport.reportingUser'), allegedAbuserUri: string(input.allegedAbuserUri, 'AbuseReport.allegedAbuserUri'), reasonCode: integer(input.reasonCode, 'AbuseReport.reasonCode'), note: text(input.note, 'AbuseReport.note'), messages: input.messages.map((item, index) => { const entry = object(item, `AbuseReport.messages[${index}]`); return { messageContent: binary(entry.messageContent, `AbuseReport.messages[${index}].messageContent`), frank: decodeFrankWire(JSON.stringify(entry.frank)), acceptedTimestamp: string(entry.acceptedTimestamp, `AbuseReport.messages[${index}].acceptedTimestamp`) } }) }
}

export function encodeMimiAbuseReportWire(value: MimiAbuseReport): string { return JSON.stringify({ ...(value.reportingUser === undefined ? {} : { reportingUser: value.reportingUser }), allegedAbuserUri: value.allegedAbuserUri, reasonCode: value.reasonCode, note: value.note, messages: value.messages.map(message => ({ messageContent: bytesToBase64url(message.messageContent), frank: JSON.parse(encodeFrankWire(message.frank)), acceptedTimestamp: message.acceptedTimestamp })) }) }

function queryElement(value: unknown, name: string): MimiIdentifierQueryElement {
  const input = object(value, name)
  const searchType = input.searchType
  if (searchType !== 'handle' && searchType !== 'nick' && searchType !== 'email' && searchType !== 'phone' && searchType !== 'partialName' && searchType !== 'wholeProfile' && searchType !== 'oidcStdClaim' && searchType !== 'vcardField') throw new MimiWireError(`${name}.searchType is invalid`)
  const fieldName = optionalString(input.fieldName, `${name}.fieldName`)
  if ((searchType === 'oidcStdClaim' || searchType === 'vcardField') !== (fieldName !== undefined)) throw new MimiWireError(`${name}.fieldName is required only for claimed fields`)
  return { searchType, searchValue: string(input.searchValue, `${name}.searchValue`), fieldName }
}

function packageArray(value: unknown, name: string): PublishedKeyPackage[] {
  if (!Array.isArray(value)) throw new MimiWireError(`${name} must be an array`)
  return value.map((entry, index) => packageValue(entry, `${name}[${index}]`))
}
function packageJson(value: PublishedKeyPackage): Record<string, unknown> {
  return { reference: bytesToBase64url(value.reference), user: value.user, client: value.client, keyPackage: bytesToBase64url(value.keyPackage), ...(value.capabilities === undefined ? {} : { capabilities: value.capabilities }), publishedAt: value.publishedAt, ...(value.expiresAt === undefined ? {} : { expiresAt: value.expiresAt }), ...(value.sourceProvider === undefined ? {} : { sourceProvider: value.sourceProvider }) }
}
function packageValue(value: unknown, name: string): PublishedKeyPackage {
  const input = object(value, name)
  return { reference: binary(input.reference, `${name}.reference`), user: string(input.user, `${name}.user`), client: string(input.client, `${name}.client`), keyPackage: binary(input.keyPackage, `${name}.keyPackage`), capabilities: input.capabilities === undefined ? undefined : object(input.capabilities, `${name}.capabilities`) as PublishedKeyPackage['capabilities'], publishedAt: string(input.publishedAt, `${name}.publishedAt`), expiresAt: optionalString(input.expiresAt, `${name}.expiresAt`), sourceProvider: optionalString(input.sourceProvider, `${name}.sourceProvider`) }
}
function JSONValue(text: string): unknown { try { return JSON.parse(text) } catch { throw new MimiWireError('MIMI HTTP body is not JSON') } }
function object(value: unknown, name: string): Record<string, unknown> { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MimiWireError(`${name} must be an object`); return value as Record<string, unknown> }
function string(value: unknown, name: string): string { if (typeof value !== 'string' || value.length === 0) throw new MimiWireError(`${name} must be a non-empty string`); return value }
function text(value: unknown, name: string): string { if (typeof value !== 'string') throw new MimiWireError(`${name} must be a string`); return value }
function integer(value: unknown, name: string): number { if (!Number.isSafeInteger(value) || (value as number) < 0) throw new MimiWireError(`${name} must be a non-negative integer`); return value as number }
function optionalString(value: unknown, name: string): string | undefined { return value === undefined ? undefined : string(value, name) }
function binary(value: unknown, name: string): Uint8Array { if (typeof value !== 'string') throw new MimiWireError(`${name} must be base64url`); try { return base64urlToBytes(value) } catch { throw new MimiWireError(`${name} must be base64url`) } }
