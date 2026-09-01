import { decodeUint8, decodeUint16, uint8Encoder, uint16Encoder } from './codec/number.js'
import { Decoder, failDecoder, flatMapDecoder, mapDecoder, mapDecoders, succeedDecoder } from './codec/tlsDecoder.js'
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from './codec/tlsEncoder.js'
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from './codec/variableLength.js'
import type { Extension } from './extension.js'

/** `draft-ietf-mls-extensions`-10 §4.6 / §7.1.1. */
export const APP_DATA_DICTIONARY_EXTENSION_TYPE = 0x0006
/** `draft-ietf-mls-extensions`-10 §4.7 / §7.2.1. */
export const APP_DATA_UPDATE_PROPOSAL_TYPE = 0x0008

export interface ComponentData { componentId: number; data: Uint8Array }
export interface AppDataDictionary { componentData: ComponentData[] }

const componentDataEncoder: BufferEncoder<ComponentData> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  value => [value.componentId, value.data] as const,
)
export const encodeComponentData: Encoder<ComponentData> = encode(componentDataEncoder)
export const decodeComponentData: Decoder<ComponentData> = mapDecoders(
  [decodeUint16, decodeVarLenData],
  (componentId, data) => ({ componentId, data }),
)

const appDataDictionaryEncoder: BufferEncoder<AppDataDictionary> = contramapBufferEncoders(
  [varLenTypeEncoder(componentDataEncoder)],
  value => [sortedUnique(value.componentData)] as const,
)
export const encodeAppDataDictionary: Encoder<AppDataDictionary> = encode(appDataDictionaryEncoder)
export const decodeAppDataDictionary: Decoder<AppDataDictionary> = mapDecoder(
  decodeVarLenType(decodeComponentData),
  componentData => ({ componentData }),
)

export type AppDataUpdateOperation = 'update' | 'remove'
export interface AppDataUpdate { componentId: number; operation: AppDataUpdateOperation; update?: Uint8Array }

export const appDataUpdateEncoder: BufferEncoder<AppDataUpdate> = (value) => {
  if (value.operation === 'update') {
    if (value.update === undefined) throw new TypeError('AppDataUpdate update operation requires update bytes')
    return contramapBufferEncoders<[number, number, Uint8Array], AppDataUpdate>([uint16Encoder, uint8Encoder, varLenDataEncoder], item => [item.componentId, 1, item.update!] as const)(value)
  }
  if (value.update !== undefined) throw new TypeError('AppDataUpdate remove operation must not contain update bytes')
  return contramapBufferEncoders<[number, number], AppDataUpdate>([uint16Encoder, uint8Encoder], item => [item.componentId, 2] as const)(value)
}
export const encodeAppDataUpdate: Encoder<AppDataUpdate> = encode(appDataUpdateEncoder)
export const decodeAppDataUpdate: Decoder<AppDataUpdate> = flatMapDecoder(
  decodeUint16,
  componentId => flatMapDecoder(decodeUint8, operation => {
    if (operation === 1) return mapDecoder(decodeVarLenData, update => ({ componentId, operation: 'update' as const, update }))
    if (operation === 2) return succeedDecoder({ componentId, operation: 'remove' as const })
    return failDecoder()
  }),
)

export function appDataDictionaryFrom(extensions: Extension[]): AppDataDictionary | undefined {
  const extension = extensions.find(value => value.extensionType === APP_DATA_DICTIONARY_EXTENSION_TYPE)
  if (!extension) return undefined
  const decoded = decodeAppDataDictionary(extension.extensionData, 0)
  if (!decoded || decoded[1] !== extension.extensionData.length || !isSortedUnique(decoded[0].componentData)) return undefined
  return decoded[0]
}

export function appDataComponent(extensions: Extension[], componentId: number): Uint8Array | undefined {
  return appDataDictionaryFrom(extensions)?.componentData.find(value => value.componentId === componentId)?.data
}

/** Applies replacement-style data updates used by components whose update is their full next value. */
export function replaceAppDataComponents(
  extensions: Extension[],
  updates: AppDataUpdate[],
): Extension[] {
  const dictionary = appDataDictionaryFrom(extensions) ?? { componentData: [] }
  const values = new Map(dictionary.componentData.map(value => [value.componentId, value.data]))
  for (const update of updates) {
    if (update.operation === 'remove') {
      if (!values.delete(update.componentId)) throw new TypeError(`cannot remove absent AppData component ${update.componentId}`)
    } else values.set(update.componentId, update.update!)
  }
  const rest = extensions.filter(value => value.extensionType !== APP_DATA_DICTIONARY_EXTENSION_TYPE)
  return [...rest, { extensionType: APP_DATA_DICTIONARY_EXTENSION_TYPE, extensionData: encodeAppDataDictionary({ componentData: [...values].map(([componentId, data]) => ({ componentId, data })) }) }]
}

function sortedUnique(values: ComponentData[]): ComponentData[] {
  const sorted = [...values].sort((a, b) => a.componentId - b.componentId)
  if (!isSortedUnique(sorted)) throw new TypeError('AppDataDictionary component IDs must be unique')
  return sorted
}

function isSortedUnique(values: ComponentData[]): boolean {
  return values.every((value, index) => Number.isInteger(value.componentId) && value.componentId >= 0 && value.componentId <= 0xffff && (index === 0 || values[index - 1]!.componentId < value.componentId))
}
