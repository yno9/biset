// DIDComm message-type URIs shared by the mediator server (mediator/server.ts)
// and its client library (mediator-coordinate.ts/mediator-pickup.ts/
// send-message.ts) -- one definition so the two sides of the wire can never
// drift apart (feedback: unify common logic rather than let each file grow
// its own copy of the same constant, which is exactly what happened across
// Phase 3/4's server.ts + mediator-coordinate.ts + mediator-pickup.ts before
// this file existed).
export const MEDIATE_REQUEST = 'https://didcomm.org/coordinate-mediation/2.0/mediate-request'
export const MEDIATE_GRANT = 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant'
export const KEYLIST_UPDATE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
export const KEYLIST_UPDATE_RESPONSE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
export const KEYLIST_QUERY = 'https://didcomm.org/coordinate-mediation/2.0/keylist-query'
export const KEYLIST = 'https://didcomm.org/coordinate-mediation/2.0/keylist'
export const FORWARD = 'https://didcomm.org/routing/2.0/forward'
export const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
export const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
export const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
export const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'
export const MESSAGES_RECEIVED = 'https://didcomm.org/messagepickup/3.0/messages-received'

// Live delivery over SSE (mediator/server.ts's `GET /stream`) -- a biset-
// specific extension, not a DIF-registered Pickup 3.0 message type: the
// spec's own pickup family is deliberately poll/pull-oriented (an offline-
// tolerant client asks when it's ready), with no live-push concept of its
// own. Modeled on the SAME watch-token pattern mls-ds/http.ts's SSE stream
// already uses, for the identical reason: `EventSource` can carry no
// request body/custom headers, so the one request that CAN be authcrypt'd
// (this one, over the mediator's ordinary POST /) mints a short-lived,
// unencrypted token the subsequent GET carries in its query string instead.
export const WATCH_REQUEST = 'https://biset.md/mediator-watch/1.0/watch-request'
export const WATCH_GRANT = 'https://biset.md/mediator-watch/1.0/watch-grant'
