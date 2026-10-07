// DIDComm message-type URIs shared by the mediator server (mediator/server.ts)
// and its client library (mediator-coordinate.ts/mediator-pickup.ts/
// send-message.ts) -- one definition so the two sides of the wire can never
// drift apart (feedback: unify common logic rather than let each file grow
// its own copy of the same constant, which is exactly what happened across
// Phase 3/4's server.ts + mediator-coordinate.ts + mediator-pickup.ts before
// this file existed).
// Coordinate Mediation 3.0. Recipients are DIDs; `device` on
// recipient-update and on each `recipient` entry is a biset extension that
// names which of the DID's devices an inbox belongs to.
export const COORDINATE_MEDIATION = 'https://didcomm.org/coordinate-mediation/3.0'
export const MEDIATE_REQUEST = `${COORDINATE_MEDIATION}/mediate-request`
export const MEDIATE_GRANT = `${COORDINATE_MEDIATION}/mediate-grant`
export const RECIPIENT_UPDATE = `${COORDINATE_MEDIATION}/recipient-update`
export const RECIPIENT_UPDATE_RESPONSE = `${COORDINATE_MEDIATION}/recipient-update-response`
export const RECIPIENT_QUERY = `${COORDINATE_MEDIATION}/recipient-query`
export const RECIPIENT = `${COORDINATE_MEDIATION}/recipient`
export const ROUTING = 'https://didcomm.org/routing/2.0'
export const FORWARD = `${ROUTING}/forward`
export const MESSAGE_PICKUP = 'https://didcomm.org/messagepickup/3.0'
export const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
export const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
export const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
export const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'
export const MESSAGES_RECEIVED = 'https://didcomm.org/messagepickup/3.0/messages-received'

// Pickup 3.0 live mode: only over a persistent connection (WebSocket), and
// only with `return_route: "all"` so the mediator may push on that socket.
export const LIVE_DELIVERY_CHANGE = 'https://didcomm.org/messagepickup/3.0/live-delivery-change'
export const LIVE_MODE_NOT_SUPPORTED_PROBLEM = 'e.m.live-mode-not-supported'

// Discover Features 2.0. A mediator discloses the protocols it speaks and
// its `max_receive_bytes` constraint (DIDComm v2.1 "Agent Constraint
// Disclosure"): the largest message it will queue for a recipient.
export const DISCOVER_FEATURES = 'https://didcomm.org/discover-features/2.0'
export const DISCOVER_FEATURES_QUERIES = `${DISCOVER_FEATURES}/queries`
export const DISCOVER_FEATURES_DISCLOSE = `${DISCOVER_FEATURES}/disclose`
export const MAX_RECEIVE_BYTES = 'max_receive_bytes'
/** A message over `max_receive_bytes` (DIDComm v2.1 transports). */
export const MESSAGE_TOO_BIG_PROBLEM = 'e.m.me.res.storage.message_too_big'

// Problem code for a recipient-update add refused because the recipient DID
// already has the mediator's maximum number of device inboxes
// (mediator/server.ts). Args: the DID, how many it has, the limit.
export const MAX_DEVICES_PROBLEM = 'e.m.req.max-devices'
