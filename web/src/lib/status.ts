import type { JobStatus, NodeHealth, NodeStatus } from '../api/types'

export interface ToneMeta {
  label: string
  /** Solid dot colour for dense status rows. */
  dot: string
  /** Pill classes: border + background + text. */
  badge: string
  /** Subtle panel accent for status blocks. */
  surface: string
}

export const NODE_STATUS_META: Record<NodeStatus, ToneMeta> = {
  pending: {
    label: 'Pending',
    dot: 'bg-dim',
    badge: 'border-line-strong bg-ink-800 text-muted',
    surface: 'border-line bg-ink-850',
  },
  running: {
    label: 'Running',
    dot: 'bg-accent motion-safe:animate-pulse',
    badge: 'border-accent/40 bg-accent/10 text-accent',
    surface: 'border-accent/25 bg-accent/[0.04]',
  },
  completed: {
    label: 'Completed',
    dot: 'bg-good',
    badge: 'border-good/40 bg-good/10 text-good',
    surface: 'border-good/20 bg-good/[0.03]',
  },
  failed: {
    label: 'Failed',
    dot: 'bg-bad',
    badge: 'border-bad/40 bg-bad/10 text-bad',
    surface: 'border-bad/20 bg-bad/[0.03]',
  },
  timed_out: {
    label: 'Timed out',
    dot: 'bg-warn',
    badge: 'border-warn/40 bg-warn/10 text-warn',
    surface: 'border-warn/20 bg-warn/[0.03]',
  },
  cancelled: {
    label: 'Cancelled',
    dot: 'bg-dim',
    badge: 'border-line-strong bg-ink-800 text-muted',
    surface: 'border-line bg-ink-850',
  },
}

export const JOB_STATUS_META: Record<JobStatus, ToneMeta> = {
  pending: {
    label: 'Pending',
    dot: 'bg-dim',
    badge: 'border-line-strong bg-ink-800 text-muted',
    surface: 'border-line bg-ink-850',
  },
  running: {
    label: 'Running',
    dot: 'bg-accent motion-safe:animate-pulse',
    badge: 'border-accent/40 bg-accent/10 text-accent',
    surface: 'border-accent/25 bg-accent/[0.04]',
  },
  completed: {
    label: 'Completed',
    dot: 'bg-good',
    badge: 'border-good/40 bg-good/10 text-good',
    surface: 'border-good/20 bg-good/[0.03]',
  },
  partial: {
    label: 'Partial',
    dot: 'bg-warn',
    badge: 'border-warn/40 bg-warn/10 text-warn',
    surface: 'border-warn/20 bg-warn/[0.03]',
  },
  failed: {
    label: 'Failed',
    dot: 'bg-bad',
    badge: 'border-bad/40 bg-bad/10 text-bad',
    surface: 'border-bad/20 bg-bad/[0.03]',
  },
  cancelled: {
    label: 'Cancelled',
    dot: 'bg-dim',
    badge: 'border-line-strong bg-ink-800 text-muted',
    surface: 'border-line bg-ink-850',
  },
}

export const HEALTH_META: Record<NodeHealth, ToneMeta> = {
  ok: {
    label: 'OK',
    dot: 'bg-good',
    badge: 'border-good/40 bg-good/10 text-good',
    surface: 'border-good/20 bg-good/[0.03]',
  },
  degraded: {
    label: 'Degraded',
    dot: 'bg-warn',
    badge: 'border-warn/40 bg-warn/10 text-warn',
    surface: 'border-warn/20 bg-warn/[0.03]',
  },
  unreachable: {
    label: 'Unreachable',
    dot: 'bg-bad',
    badge: 'border-bad/40 bg-bad/10 text-bad',
    surface: 'border-bad/20 bg-bad/[0.03]',
  },
  unknown: {
    label: 'Unknown',
    dot: 'bg-muted',
    badge: 'border-line-strong bg-ink-800 text-muted',
    surface: 'border-line bg-ink-850',
  },
  disabled: {
    label: 'Disabled',
    dot: 'bg-dim',
    badge: 'border-line text-dim',
    surface: 'border-line bg-ink-850',
  },
}

export function nodeStatusMeta(status: NodeStatus | string): ToneMeta {
  return NODE_STATUS_META[status as NodeStatus] ?? NODE_STATUS_META.pending
}

export function jobStatusMeta(status: JobStatus | string): ToneMeta {
  return JOB_STATUS_META[status as JobStatus] ?? JOB_STATUS_META.pending
}

export function healthMeta(health: NodeHealth | string): ToneMeta {
  return HEALTH_META[health as NodeHealth] ?? HEALTH_META.unknown
}

const TERMINAL_JOB_STATUSES: ReadonlySet<string> = new Set([
  'completed',
  'partial',
  'failed',
  'cancelled',
])

const TERMINAL_NODE_STATUSES: ReadonlySet<string> = new Set([
  'completed',
  'failed',
  'timed_out',
  'cancelled',
])

export function isTerminalJob(status: JobStatus | string | undefined): boolean {
  return status != null && TERMINAL_JOB_STATUSES.has(status)
}

export function isTerminalNode(status: NodeStatus | string | undefined): boolean {
  return status != null && TERMINAL_NODE_STATUSES.has(status)
}

export function nodeStatusLabel(status: NodeStatus | string): string {
  return nodeStatusMeta(status).label
}
