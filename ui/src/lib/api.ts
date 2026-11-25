import { prefix } from "@/lib/page"

/** An error from localoidc: an OAuth error response, or no response at all (status 0). */
export class ApiError extends Error {
  status: number
  data: unknown

  constructor(message: string, status: number, data: unknown) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.data = data
  }
}

type OAuthError = { error?: string; error_description?: string }

/** Calls one of this issuer's endpoints, such as `/dev/api/token`. */
export async function api<T>(
  path: string,
  {
    method = "GET",
    body,
    signal,
  }: { method?: string; body?: unknown; signal?: AbortSignal } = {}
): Promise<T> {
  const headers = new Headers()
  if (body !== undefined) headers.set("Content-Type", "application/json")
  let response: Response
  try {
    response = await fetch(prefix + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      signal,
    })
  } catch (e) {
    if (signal?.aborted) throw e
    throw new ApiError(
      "localsaml isn't responding. Is it still running?",
      0,
      null
    )
  }
  let data: unknown = null
  try {
    data = await response.json()
  } catch {
    // No content, or not JSON.
  }
  if (!response.ok) {
    const error = (data ?? {}) as OAuthError
    throw new ApiError(
      error.error_description ??
        error.error ??
        `${response.status} ${response.statusText}`,
      response.status,
      data
    )
  }
  return data as T
}

export const message = (e: unknown) =>
  e instanceof Error ? e.message : String(e)
