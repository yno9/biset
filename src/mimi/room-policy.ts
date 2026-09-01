/**
 * Draft MIMI room-policy semantic evaluator.
 *
 * The draft currently assigns the Roles component a TBD MLS component ID, so
 * this module deliberately consumes normalized policy data rather than
 * inventing a permanent encoding for RoomState.basePolicy.  A future MLS
 * extension decoder can feed that normalized data here without changing the
 * authorization rules.
 */
import type { MimiUserUri, ParticipantListData, UserRolePair } from './protocol-types.ts'

export type MimiRoleCapability =
  | 'canAddParticipant'
  | 'canRemoveParticipant'
  | 'canRemoveSelf'
  | 'canChangeUserRole'
  | 'canSendMessage'
  | 'canReceiveMessage'

export interface RoleChangeTargets {
  fromRoleIndex: number
  targetRoleIndexes: number[]
}

export interface MimiRoomRole {
  roleIndex: number
  capabilities: MimiRoleCapability[]
  minimumParticipants: number
  maximumParticipants?: number
  minimumActiveParticipants: number
  maximumActiveParticipants?: number
  authorizedRoleChanges: RoleChangeTargets[]
}

export interface MimiRoomPolicy {
  roles: MimiRoomRole[]
}

export type RoomPolicyDecision = { allowed: true } | { allowed: false; reason: string }

/** Validates role definitions independently of a room state transition. */
export function validateRoomPolicy(policy: MimiRoomPolicy): void {
  if (!Array.isArray(policy.roles) || policy.roles.length === 0) throw new TypeError('room policy requires at least one role')
  const indexes = new Set<number>()
  for (const role of policy.roles) {
    validIndex(role.roleIndex, 'role index')
    if (indexes.has(role.roleIndex)) throw new TypeError('room policy contains duplicate role indexes')
    indexes.add(role.roleIndex)
    validCount(role.minimumParticipants, 'minimum participant constraint')
    validCount(role.minimumActiveParticipants, 'minimum active participant constraint')
    optionalCount(role.maximumParticipants, 'maximum participant constraint')
    optionalCount(role.maximumActiveParticipants, 'maximum active participant constraint')
    if (role.maximumParticipants !== undefined && role.maximumParticipants < role.minimumParticipants) throw new TypeError('maximum participant constraint is below the minimum')
    if (role.maximumActiveParticipants !== undefined && role.maximumActiveParticipants < role.minimumActiveParticipants) throw new TypeError('maximum active participant constraint is below the minimum')
    if (new Set(role.capabilities).size !== role.capabilities.length) throw new TypeError('role has duplicate capabilities')
    const transitionSources = new Set<number>()
    for (const transition of role.authorizedRoleChanges) {
      validIndex(transition.fromRoleIndex, 'role transition source')
      if (transitionSources.has(transition.fromRoleIndex)) throw new TypeError('role has duplicate transition sources')
      transitionSources.add(transition.fromRoleIndex)
      if (transition.targetRoleIndexes.length === 0) throw new TypeError('role transition requires a target role')
      for (const target of transition.targetRoleIndexes) validIndex(target, 'role transition target')
    }
  }
  // Index zero represents people absent from the participant list.  It must
  // exist for additions/removals to be expressible, but never grants powers.
  if (!indexes.has(0)) throw new TypeError('room policy requires reserved role index zero')
  for (const role of policy.roles) for (const transition of role.authorizedRoleChanges) {
    if (!indexes.has(transition.fromRoleIndex) || transition.targetRoleIndexes.some(index => !indexes.has(index))) throw new TypeError('role transition references an undefined role')
  }
}

/**
 * Evaluates participant-list changes made by a current room member.  External
 * joins and preauthorization require credentials outside this module and are
 * intentionally left to the later federation boundary.
 */
export function authorizeParticipantListTransition(
  policy: MimiRoomPolicy,
  current: ParticipantListData,
  next: ParticipantListData,
  actor: MimiUserUri,
): RoomPolicyDecision {
  try {
    validateRoomPolicy(policy)
    validateParticipantList(current, policy, 'current')
    validateParticipantList(next, policy, 'next')
  } catch (error) {
    return denied(error instanceof Error ? error.message : 'invalid room policy')
  }

  const currentByUser = participantMap(current)
  const nextByUser = participantMap(next)
  const actorEntry = currentByUser.get(actor)
  if (!actorEntry) return denied('external joins require preauthorization handling')
  const actorRole = roleFor(policy, actorEntry.roleIndex)!
  const additions = [...nextByUser.values()].filter(entry => !currentByUser.has(entry.user))
  const removals = [...currentByUser.values()].filter(entry => !nextByUser.has(entry.user))
  const changes = [...nextByUser.values()].filter(entry => currentByUser.get(entry.user)?.roleIndex !== undefined && currentByUser.get(entry.user)!.roleIndex !== entry.roleIndex)

  for (const target of additions) {
    if (target.user === actor || !hasCapability(actorRole, 'canAddParticipant')) return denied('actor cannot add this participant')
    if (!allowsTransition(actorRole, 0, target.roleIndex)) return denied('actor cannot assign the target role')
  }
  for (const target of removals) {
    const self = target.user === actor
    if (self ? !hasCapability(actorRole, 'canRemoveSelf') : !hasCapability(actorRole, 'canRemoveParticipant')) return denied('actor cannot remove this participant')
    if (!allowsTransition(actorRole, target.roleIndex, 0)) return denied('actor cannot remove the target role')
  }
  for (const target of changes) {
    if (target.user === actor) return denied('self role changes require preauthorization handling')
    const before = currentByUser.get(target.user)!
    if (!hasCapability(actorRole, 'canChangeUserRole') || !allowsTransition(actorRole, before.roleIndex, target.roleIndex)) return denied('actor cannot change the target role')
  }
  for (const entry of currentByUser.values()) {
    const replacement = nextByUser.get(entry.user)
    if (replacement && !sameClientSet(entry, replacement)) return denied('client membership changes are not participant-list role changes')
  }
  try { validateRoleCounts(policy, next) } catch (error) { return denied(error instanceof Error ? error.message : 'role constraints are not satisfied') }
  return { allowed: true }
}

/** Hub-enforceable message-send check; content-level capabilities remain client-side. */
export function maySendMessage(policy: MimiRoomPolicy, participants: ParticipantListData, user: MimiUserUri): boolean {
  try {
    validateRoomPolicy(policy)
    validateParticipantList(participants, policy, 'participant list')
  } catch { return false }
  const participant = participantMap(participants).get(user)
  return participant !== undefined && hasCapability(roleFor(policy, participant.roleIndex)!, 'canSendMessage')
}

function validateParticipantList(list: ParticipantListData, policy: MimiRoomPolicy, name: string): void {
  const users = new Set<string>()
  for (const entry of list.participants) {
    if (!entry.user || users.has(entry.user)) throw new TypeError(`${name} participant list has duplicate or empty users`)
    users.add(entry.user)
    if (entry.roleIndex === 0 || !roleFor(policy, entry.roleIndex)) throw new TypeError(`${name} participant has an undefined or reserved role`)
  }
}

function validateRoleCounts(policy: MimiRoomPolicy, participants: ParticipantListData): void {
  for (const role of policy.roles) {
    if (role.roleIndex === 0) continue
    const matching = participants.participants.filter(entry => entry.roleIndex === role.roleIndex)
    const active = matching.filter(entry => (entry.clientIds?.length ?? 0) > 0).length
    if (matching.length < role.minimumParticipants || (role.maximumParticipants !== undefined && matching.length > role.maximumParticipants)) throw new TypeError(`participant count violates role ${role.roleIndex} constraints`)
    if (active < role.minimumActiveParticipants || (role.maximumActiveParticipants !== undefined && active > role.maximumActiveParticipants)) throw new TypeError(`active participant count violates role ${role.roleIndex} constraints`)
  }
}

function participantMap(list: ParticipantListData): Map<MimiUserUri, UserRolePair> { return new Map(list.participants.map(entry => [entry.user, entry])) }
function roleFor(policy: MimiRoomPolicy, index: number): MimiRoomRole | undefined { return policy.roles.find(role => role.roleIndex === index) }
function hasCapability(role: MimiRoomRole, capability: MimiRoleCapability): boolean { return role.capabilities.includes(capability) }
function allowsTransition(role: MimiRoomRole, from: number, to: number): boolean { return role.authorizedRoleChanges.some(change => change.fromRoleIndex === from && change.targetRoleIndexes.includes(to)) }
function sameClientSet(left: UserRolePair, right: UserRolePair): boolean { return JSON.stringify(left.clientIds ?? []) === JSON.stringify(right.clientIds ?? []) }
function denied(reason: string): RoomPolicyDecision { return { allowed: false, reason } }
function validIndex(value: number, name: string): void { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative integer`) }
function validCount(value: number, name: string): void { if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative integer`) }
function optionalCount(value: number | undefined, name: string): void { if (value !== undefined) validCount(value, name) }
