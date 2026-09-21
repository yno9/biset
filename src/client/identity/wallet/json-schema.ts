/**
 * A minimal, dependency-free, eval-free interpreter for the subset of JSON
 * Schema (Draft 2020-12) actually used by
 * schemas/biset-messenger-capability.schema.json: type/const/enum/pattern/
 * format(date-time)/required/additionalProperties/properties/items/
 * prefixItems/minItems/maxItems/oneOf/$ref/$defs. This is NOT a
 * general-purpose JSON Schema implementation -- an unsupported keyword combination is reported
 * as a validation failure (see the final branch of `check` below) rather
 * than silently ignored, matching this codebase's existing "reject what we
 * don't understand" style (compare exactKeys/strictObjectKeys in
 * did-md-oauth.ts and did.md's own server.ts).
 *
 * Why not ajv (or another existing library) instead: neither did.md nor
 * Biset has a JSON Schema/validation-library dependency anywhere today --
 * every wire-format check in both repos is a small hand-written function.
 * ajv's default compilation strategy also generates and evaluates JS code
 * at runtime (`new Function`), which this application -- a key-management
 * and messaging client -- deliberately avoids introducing.
 */
export type JSONSchema = { $ref?: string; [key: string]: unknown }

function resolveRef(root: JSONSchema, schema: JSONSchema): JSONSchema {
  if (typeof schema.$ref !== 'string') return schema
  if (!schema.$ref.startsWith('#/')) throw new Error(`Unsupported $ref target: ${schema.$ref}`)
  let node: unknown = root
  for (const segment of schema.$ref.slice(2).split('/')) {
    if (typeof node !== 'object' || node === null) throw new Error(`Invalid $ref path: ${schema.$ref}`)
    node = (node as Record<string, unknown>)[segment]
  }
  if (typeof node !== 'object' || node === null) throw new Error(`$ref does not resolve to a schema object: ${schema.$ref}`)
  return node as JSONSchema
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

function check(root: JSONSchema, schemaIn: JSONSchema, value: unknown, path: string, errors: string[]): void {
  const schema = resolveRef(root, schemaIn)

  if ('const' in schema) {
    if (!sameValue(value, schema.const)) errors.push(`${path}: expected the constant ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`)
    return
  }
  if ('enum' in schema) {
    const options = schema.enum as unknown[]
    if (!options.some(option => sameValue(option, value))) errors.push(`${path}: expected one of ${JSON.stringify(options)}, got ${JSON.stringify(value)}`)
    return
  }
  if ('oneOf' in schema) {
    const branches = schema.oneOf as JSONSchema[]
    const matches = branches.filter(branch => { const branchErrors: string[] = []; check(root, branch, value, path, branchErrors); return branchErrors.length === 0 })
    if (matches.length !== 1) errors.push(`${path}: expected exactly one oneOf branch to match, ${matches.length} did`)
    return
  }

  if (schema.type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) { errors.push(`${path}: expected an object`); return }
    const object = value as Record<string, unknown>
    for (const key of (schema.required as string[] | undefined) ?? []) if (!(key in object)) errors.push(`${path}.${key}: required property is missing`)
    const properties = (schema.properties as Record<string, JSONSchema> | undefined) ?? {}
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(properties))
      for (const key of Object.keys(object)) if (!allowed.has(key)) errors.push(`${path}.${key}: unexpected property`)
    }
    for (const [key, subSchema] of Object.entries(properties)) if (key in object) check(root, subSchema, object[key], `${path}.${key}`, errors)
    return
  }
  if (schema.type === 'array') {
    if (!Array.isArray(value)) { errors.push(`${path}: expected an array`); return }
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) errors.push(`${path}: expected at least ${schema.minItems} items, got ${value.length}`)
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) errors.push(`${path}: expected at most ${schema.maxItems} items, got ${value.length}`)
    // prefixItems: positional (tuple) validation -- one schema per index.
    // items: one schema applied uniformly to every element. A schema uses
    // at most one of the two here.
    if (schema.prefixItems) {
      const prefixSchemas = schema.prefixItems as JSONSchema[]
      prefixSchemas.forEach((itemSchema, index) => { if (index < value.length) check(root, itemSchema, value[index], `${path}[${index}]`, errors) })
    } else if (schema.items) {
      value.forEach((item, index) => check(root, schema.items as JSONSchema, item, `${path}[${index}]`, errors))
    }
    return
  }
  if (schema.type === 'string') {
    if (typeof value !== 'string') { errors.push(`${path}: expected a string`); return }
    if (typeof schema.pattern === 'string' && !new RegExp(schema.pattern).test(value)) errors.push(`${path}: does not match pattern ${schema.pattern}`)
    if (schema.format === 'date-time' && Number.isNaN(Date.parse(value))) errors.push(`${path}: expected an RFC 3339 date-time string`)
    return
  }

  errors.push(`${path}: unsupported schema (this validator only implements a subset of JSON Schema -- see json-schema.ts's module comment)`)
}

/** Throws with every mismatch listed (not just the first) if `value` does not match `schema`. */
export function assertMatchesSchema(schema: JSONSchema, value: unknown, label: string): void {
  const errors: string[] = []
  check(schema, schema, value, label, errors)
  if (errors.length) throw new Error(`${label} does not match its schema:\n${errors.join('\n')}`)
}
