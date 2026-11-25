// Per-browser state: saved identities, the last one used and the request inspector's filters.
// Storage can be blocked, so every read and write tolerates failure. Values are JSON, under the
// keys the previous UI used.

const PREFIX = "localsaml."

export function load<T>(key: string, fallback: T): T {
  try {
    const value = localStorage.getItem(PREFIX + key)
    return value == null ? fallback : ((JSON.parse(value) as T) ?? fallback)
  } catch {
    return fallback
  }
}

export function save(key: string, value: unknown) {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value))
  } catch {
    // Not kept; the page still works.
  }
}
