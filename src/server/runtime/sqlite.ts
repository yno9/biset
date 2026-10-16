/** A small `bun:sqlite`-shaped wrapper over `node:sqlite`, so the stores keep one query style. */
import { DatabaseSync, type SQLInputValue, type StatementSync } from 'node:sqlite'

export class Statement<Row, Params extends unknown[]> {
  constructor(private readonly statement: StatementSync) {}
  /** The first row, or null (as bun:sqlite does; node:sqlite says undefined). */
  get(...params: Params): Row | null { return (this.statement.get(...bind(params)) as Row | undefined) ?? null }
  all(...params: Params): Row[] { return this.statement.all(...bind(params)) as Row[] }
  run(...params: Params): { changes: number } { return { changes: Number(this.statement.run(...bind(params)).changes) } }
}

export class Database {
  private readonly database: DatabaseSync
  private readonly statements = new Map<string, Statement<never, never>>()
  private depth = 0

  constructor(path: string, _options?: { create?: boolean }) { this.database = new DatabaseSync(path) }

  query<Row = unknown, Params extends unknown[] = unknown[]>(sql: string): Statement<Row, Params> {
    let statement = this.statements.get(sql)
    if (!statement) { statement = new Statement(this.database.prepare(sql)); this.statements.set(sql, statement) }
    return statement as unknown as Statement<Row, Params>
  }

  run(sql: string, ...params: unknown[]): { changes: number } {
    return params.length ? this.query(sql).run(...params) : (this.database.exec(sql), { changes: 0 })
  }

  exec(sql: string): void { this.database.exec(sql) }

  /** A function running `operation` in a transaction; nested calls become savepoints. */
  transaction<T>(operation: () => T): () => T {
    return () => {
      const name = `biset_${this.depth}`
      this.database.exec(this.depth === 0 ? 'BEGIN' : `SAVEPOINT ${name}`)
      this.depth += 1
      try {
        const result = operation()
        this.depth -= 1
        this.database.exec(this.depth === 0 ? 'COMMIT' : `RELEASE ${name}`)
        return result
      } catch (error) {
        this.depth -= 1
        this.database.exec(this.depth === 0 ? 'ROLLBACK' : `ROLLBACK TO ${name}; RELEASE ${name}`)
        throw error
      }
    }
  }

  close(): void { this.statements.clear(); this.database.close() }
}

// node:sqlite refuses booleans and undefined where bun:sqlite stored 1/0 and NULL.
function bind(params: unknown[]): SQLInputValue[] {
  return params.map(value => typeof value === 'boolean' ? Number(value) : value === undefined ? null : value) as SQLInputValue[]
}
