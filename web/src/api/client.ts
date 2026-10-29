import type {
  CreateJobRequest,
  JobList,
  JobResponse,
  LoginRequest,
  NodeList,
  ResolveResponse,
  Session,
} from './types'

/**
 * The CSRF token lives only in module memory: it is never written to
 * localStorage, cookies or sessionStorage. Every state-changing request sends
 * it as `X-TraceCat-CSRF`, as required by docs/API.md §2.2.
 */
let csrfToken: string | null = null

export function setCsrfToken(token: string | null | undefined): void {
  csrfToken = token && token.length > 0 ? token : null
}

export function getCsrfToken(): string | null {
  return csrfToken
}

/** Error carrying the stable server error envelope plus HTTP metadata. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly retryAfterMs?: number

  constructor(status: number, code: string, message: string, retryAfterMs?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfterMs = retryAfterMs
  }

  /** True when the UI should send the user back to the login screen. */
  get isUnauthorized(): boolean {
    return this.status === 401
  }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (error instanceof DOMException && error.name === 'AbortError') {
    return new ApiError(0, 'aborted', 'The request was cancelled.')
  }
  if (error instanceof TypeError) {
    return new ApiError(
      0,
      'network_error',
      'Could not reach the controller. Check the connection and retry.',
    )
  }
  const message = error instanceof Error ? error.message : 'Unexpected client error.'
  return new ApiError(0, 'client_error', message)
}

function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined
  const seconds = Number(header.trim())
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000)
  const date = Date.parse(header)
  if (Number.isFinite(date)) {
    const delta = date - Date.now()
    return delta > 0 ? delta : 0
  }
  return undefined
}

async function parseFailure(response: Response): Promise<ApiError> {
  const retryAfterMs = parseRetryAfter(response.headers.get('Retry-After'))
  let code = `http_${response.status}`
  let message =
    response.status === 502 || response.status === 503 || response.status === 504
      ? `The Controller is unreachable through its proxy/tunnel (HTTP ${response.status}).`
      : `Request failed with status ${response.status}.`
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && 'error' in body) {
      const envelope = (body as { error?: unknown }).error
      if (envelope && typeof envelope === 'object') {
        const { code: c, message: m } = envelope as { code?: unknown; message?: unknown }
        if (typeof c === 'string' && c.length > 0) code = c
        if (typeof m === 'string' && m.length > 0) message = m
      }
    }
  } catch {
    // Non-JSON error bodies (proxy failures, empty responses) keep the fallback.
  }
  return new ApiError(response.status, code, message, retryAfterMs)
}

interface RequestOptions {
  method?: 'GET' | 'POST'
  body?: unknown
  csrf?: boolean
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  const needsCsrf = options.csrf !== false && method !== 'GET'
  if (needsCsrf && csrfToken) headers['X-TraceCat-CSRF'] = csrfToken
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'

  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      cache: 'no-store',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch (error) {
    throw toApiError(error)
  }

  if (!response.ok) throw await parseFailure(response)
  if (response.status === 204) return undefined as T

  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes('application/json')) {
    return undefined as T
  }
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError(response.status, 'invalid_response', 'The controller returned malformed JSON.')
  }
}

/* ------------------------------------------------------------------ */
/* Session and authentication                                          */
/* ------------------------------------------------------------------ */

/**
 * GET /api/v1/session. Resolves with the session when authenticated and throws
 * `ApiError(401, ...)` when it is not. The CSRF token is retained in memory.
 */
export async function fetchSession(): Promise<Session> {
  const session = await request<Session>('/api/v1/session')
  setCsrfToken(session.csrf_token)
  return session
}

/** POST /api/v1/auth/login (local auth mode only). */
export async function login(password: string): Promise<Session> {
  const body: LoginRequest = { password }
  const session = await request<Session>('/api/v1/auth/login', { method: 'POST', body })
  setCsrfToken(session.csrf_token)
  return session
}

/** POST /api/v1/auth/logout (local auth mode only). */
export async function logout(): Promise<void> {
  try {
    await request<void>('/api/v1/auth/logout', { method: 'POST' })
  } finally {
    setCsrfToken(null)
  }
}

/* ------------------------------------------------------------------ */
/* Targets, nodes and jobs                                             */
/* ------------------------------------------------------------------ */

/** POST /api/v1/resolve — central DNS resolution / IP literal validation. */
export function resolveTarget(target: string): Promise<ResolveResponse> {
  return request<ResolveResponse>('/api/v1/resolve', { method: 'POST', body: { target } })
}

/** GET /api/v1/nodes — administratively configured agents. */
export function listNodes(): Promise<NodeList> {
  return request<NodeList>('/api/v1/nodes')
}

/** POST /api/v1/jobs — dispatch one distributed trace. */
export function createJob(body: CreateJobRequest): Promise<JobResponse> {
  return request<JobResponse>('/api/v1/jobs', { method: 'POST', body })
}

/** GET /api/v1/jobs/{id} — full job document. */
export function getJob(id: string): Promise<JobResponse> {
  return request<JobResponse>(`/api/v1/jobs/${encodeURIComponent(id)}`)
}

/** GET /api/v1/jobs?limit=N — bounded, newest-first history. */
export function listJobs(limit: number): Promise<JobList> {
  const bounded = Math.min(Math.max(Math.trunc(limit), 1), 100)
  return request<JobList>(`/api/v1/jobs?limit=${bounded}`)
}

/** POST /api/v1/jobs/{id}/cancel — best-effort, idempotent cancellation. */
export function cancelJob(id: string): Promise<JobResponse> {
  return request<JobResponse>(`/api/v1/jobs/${encodeURIComponent(id)}/cancel`, {
    method: 'POST',
  })
}

/** SSE stream URL for a job's state-change notifications (GET, no CSRF). */
export function jobEventsUrl(id: string): string {
  return `/api/v1/jobs/${encodeURIComponent(id)}/events`
}

/**
 * GET /api/v1/jobs/{id}/export, saved through a Blob download. The server
 * sends a Content-Disposition attachment; we keep a client-side filename of
 * `tracecat-<job id>.json` as required by the dashboard UX.
 */
export async function downloadJobExport(id: string): Promise<void> {
  let response: Response
  try {
    response = await fetch(`/api/v1/jobs/${encodeURIComponent(id)}/export`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
    })
  } catch (error) {
    throw toApiError(error)
  }
  if (!response.ok) throw await parseFailure(response)

  const blob = await response.blob()
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = `tracecat-${id}.json`
  anchor.rel = 'noopener'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000)
}
