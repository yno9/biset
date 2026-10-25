// The errors of resolving a did:vh (didvh-spec: DID Resolution Errors). In a file of their own so that the identifier and the web
// location rules can raise them without importing the resolver, which imports them.
type VhErrorCode = 'invalidDid' | 'invalidOptions' | 'invalidLog' | 'notFound' | 'featureNotSupported'

export class VhResolutionError extends Error {
  readonly code: VhErrorCode
  constructor(code: VhErrorCode, message: string) {
    super(message)
    this.name = 'VhResolutionError'
    this.code = code
  }
}
