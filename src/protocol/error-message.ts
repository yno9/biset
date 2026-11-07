/** What a caught value says, for a log line or a notice: an Error's message, or the value as text. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
