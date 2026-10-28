/**
 * TypeScript mirror of the TraceCat controller wire contract.
 *
 * Source of truth: docs/API.md §2 and internal/model/*.go. Field names must
 * match the Go JSON tags exactly; do not add client-only fields to these
 * shapes. Optional (`?`) fields are omitted by the server when unknown —
 * never synthesize defaults for them.
 */

export type IPFamily = 'ipv4' | 'ipv6'
export type Protocol = 'icmp'

export type NodeStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'timed_out'
  | 'cancelled'

export type JobStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled'

export type NodeHealth = 'ok' | 'degraded' | 'unreachable' | 'unknown' | 'disabled'

export type AuthMode = 'dev' | 'local' | 'cloudflare'

/** Stable error envelope used by every non-2xx controller response. */
export interface ApiErrorBody {
  code: string
  message: string
}

export interface ControllerLimits {
  max_hops: number
  max_queries: number
  max_execution_ms: number
  min_execution_ms: number
  max_nodes_per_job: number
  max_addresses: number
  max_history_jobs: number
}

export interface User {
  email?: string
  subject?: string
  auth_method?: string
}

/** GET /api/v1/session */
export interface Session {
  authenticated: boolean
  mode: AuthMode | string
  user?: User
  csrf_token?: string
  limits: ControllerLimits
  version: string
  warnings?: string[]
}

export interface LoginRequest {
  password: string
}

/** POST /api/v1/resolve */
export interface ResolveRequest {
  target: string
}

export interface ResolvedAddress {
  ip: string
  family: IPFamily
}

export interface ResolveResponse {
  input: string
  kind: 'ip' | 'domain' | string
  addresses: ResolvedAddress[]
  requires_selection: boolean
  truncated: boolean
  warnings?: string[]
}

/** GET /api/v1/nodes */
export interface NodeInfo {
  id: string
  name: string
  location?: string
  provider?: string
  enabled: boolean
  health: NodeHealth | string
  last_seen?: string
  nexttrace_version?: string
}

export interface NodeList {
  nodes: NodeInfo[]
}

/** POST /api/v1/jobs */
export interface CreateJobRequest {
  target_ip: string
  original_target: string
  node_ids: string[]
  protocol: Protocol
  max_hops: number
  queries: number
  timeout_ms: number
}

/**
 * One normalized probe reply (or lack of reply) for a single TTL.
 * `success=false` probes have no address; `error_code` is `no_reply`,
 * `unreachable` or `unknown`. `no_reply` is not proof the route is broken.
 */
export interface Probe {
  success: boolean
  address?: string
  ptr?: string
  rtt_ms?: number
  error_code?: string
  asn?: number
  as_name?: string
  country?: string
  region?: string
  city?: string
  owner?: string
  isp?: string
  prefix?: string
  lat?: number
  lng?: number
  mpls?: string[]
}

/** All probes observed for one TTL, grouped by the controller/agent. */
export interface Hop {
  ttl: number
  probes: Probe[]
}

export interface TraceSummary {
  hop_count: number
  reached_destination: boolean
  destination_rtt_ms?: number
  replies: number
  probes: number
}

export interface NodeResult {
  node_id: string
  node_name: string
  location?: string
  provider?: string
  status: NodeStatus
  started_at?: string
  ended_at?: string
  duration_ms?: number
  nexttrace_version?: string
  parser_schema?: string
  summary?: TraceSummary
  hops?: Hop[]
  error?: ApiErrorBody | null
}

export interface JobSummary {
  total: number
  pending: number
  running: number
  completed: number
  failed: number
  timed_out: number
  cancelled: number
  reached: number
}

/** Full job document returned by GET /api/v1/jobs/{id} and SSE events. */
export interface Job {
  schema_version: string
  id: string
  status: JobStatus
  target_ip: string
  original_target: string
  family: IPFamily
  protocol: Protocol
  max_hops: number
  queries: number
  timeout_ms: number
  created_at: string
  started_at?: string
  ended_at?: string
  created_by?: string
  nodes: NodeResult[]
  summary: JobSummary
}

/** Bounded history entry; hops are omitted. */
export interface JobListItem {
  id: string
  status: JobStatus
  target_ip: string
  original_target: string
  family: IPFamily
  created_at: string
  ended_at?: string
  summary: JobSummary
}

export interface JobList {
  jobs: JobListItem[]
}

export interface JobResponse {
  job: Job
}

/** Downloadable representation returned by GET /api/v1/jobs/{id}/export. */
export interface JobExport {
  schema_version: string
  exported_at: string
  job: Job
  raw_results?: Record<string, unknown>
}
