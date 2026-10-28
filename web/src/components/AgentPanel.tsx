import { useMemo } from 'react'
import type { ApiError } from '../api/client'
import type { NodeInfo } from '../api/types'
import { absoluteTimestamp, relativeTime } from '../lib/format'
import { healthMeta } from '../lib/status'
import { IconRefresh, IconServer } from './Icons'
import { EmptyState, ErrorNote, Skeleton, Spinner } from './ui'

const HEALTH_RANK: Record<string, number> = {
  ok: 0,
  degraded: 1,
  unknown: 2,
  unreachable: 3,
  disabled: 4,
}

function sortNodes(nodes: NodeInfo[]): NodeInfo[] {
  return [...nodes].sort((left, right) => {
    if (left.enabled !== right.enabled) return left.enabled ? -1 : 1
    const healthDelta =
      (HEALTH_RANK[left.health] ?? 5) - (HEALTH_RANK[right.health] ?? 5)
    if (healthDelta !== 0) return healthDelta
    return left.name.localeCompare(right.name)
  })
}

export function AgentPanel({
  nodes,
  loading,
  error,
  selectedIds,
  maxNodes,
  onToggle,
  onSelectAll,
  onClear,
  onRefresh,
}: {
  nodes: NodeInfo[]
  loading: boolean
  error: ApiError | null
  selectedIds: ReadonlySet<string>
  maxNodes: number
  onToggle: (id: string) => void
  onSelectAll: () => void
  onClear: () => void
  onRefresh: () => void
}) {
  const sorted = useMemo(() => sortNodes(nodes), [nodes])
  const enabledCount = useMemo(() => nodes.filter((node) => node.enabled).length, [nodes])
  const atLimit = selectedIds.size >= maxNodes

  return (
    <section className="panel" aria-labelledby="agents-heading">
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-3 py-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] leading-none text-accent/80">02</span>
            <h2
              id="agents-heading"
              className="font-mono text-[11px] font-semibold uppercase leading-none tracking-[0.16em] text-fg-soft"
            >
              Agents
            </h2>
          </div>
          <p className="mt-1 text-[11px] text-muted">
            {enabledCount} enabled · select up to {maxNodes} per job
          </p>
        </div>
        <button
          type="button"
          className="btn btn-ghost btn-xs shrink-0"
          onClick={onRefresh}
          disabled={loading}
          aria-label="Refresh agent health"
          title="Refresh agents"
        >
          {loading ? <Spinner className="h-3 w-3" /> : <IconRefresh className="h-3 w-3" />}
        </button>
      </header>

      <div className="px-3 py-2.5">
        {loading && nodes.length === 0 ? (
          <div className="space-y-1.5" aria-hidden="true">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : null}

        {error ? (
          <ErrorNote error={error} onRetry={onRefresh} compact />
        ) : null}

        {!loading && !error && nodes.length === 0 ? (
          <EmptyState
            title="No agents configured"
            icon={<IconServer className="h-5 w-5" />}
            action={
              <button type="button" className="btn btn-ghost btn-xs" onClick={onRefresh}>
                Refresh
              </button>
            }
          >
            The controller is not configured with any agent nodes. Ask the administrator to add
            agents to the controller configuration.
          </EmptyState>
        ) : null}

        {sorted.length > 0 ? (
          <>
            <ul className="space-y-1">
              {sorted.map((node) => {
                const selected = selectedIds.has(node.id)
                const disabled = !node.enabled || (!selected && atLimit)
                const health = node.enabled ? healthMeta(node.health) : healthMeta('disabled')
                return (
                  <li key={node.id}>
                    <label
                      className={`flex items-start gap-2 rounded border px-2 py-1.5 transition-colors ${
                        !node.enabled
                          ? 'cursor-not-allowed border-line/60 bg-ink-950/40 opacity-70'
                          : selected
                            ? 'cursor-pointer border-accent/45 bg-accent/[0.055]'
                            : 'cursor-pointer border-line bg-ink-950/40 hover:border-line-strong hover:bg-ink-850/60'
                      }`}
                      title={
                        !node.enabled
                          ? 'Disabled by the controller administrator'
                          : !selected && atLimit
                            ? `Selection limit of ${maxNodes} reached`
                            : undefined
                      }
                    >
                      <input
                        type="checkbox"
                        className="check-input mt-0.5"
                        checked={selected}
                        disabled={disabled}
                        onChange={() => onToggle(node.id)}
                        aria-label={`Select agent ${node.name}${node.enabled ? '' : ' (disabled)'}`}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
                          <span className="truncate text-[12px] font-medium text-fg">
                            {node.name}
                          </span>
                          <span className="font-mono text-[9px] text-dim">{node.id}</span>
                          <span
                            className={`badge badge-square ml-auto ${health.badge}`}
                            title={`Agent health: ${health.label}`}
                          >
                            <span className={`h-1 w-1 rounded-full ${health.dot}`} aria-hidden="true" />
                            {health.label}
                          </span>
                        </span>
                        <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-[10px] leading-snug text-muted">
                          {node.location ? <span className="truncate">{node.location}</span> : null}
                          {node.provider ? (
                            <>
                              <span aria-hidden="true" className="text-dim">
                                ·
                              </span>
                              <span className="truncate">{node.provider}</span>
                            </>
                          ) : null}
                          {node.nexttrace_version ? (
                            <>
                              <span aria-hidden="true" className="text-dim">
                                ·
                              </span>
                              <span className="font-mono text-dim">
                                nt {node.nexttrace_version}
                              </span>
                            </>
                          ) : null}
                          {node.last_seen ? (
                            <>
                              <span aria-hidden="true" className="text-dim">
                                ·
                              </span>
                              <span
                                className="text-dim"
                                title={`Last seen ${absoluteTimestamp(node.last_seen)}`}
                              >
                                seen {relativeTime(node.last_seen)}
                              </span>
                            </>
                          ) : null}
                        </span>
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>

            <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-line/70 pt-2">
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                onClick={onSelectAll}
                disabled={loading || enabledCount === 0 || atLimit}
                title={atLimit ? `Selection limit of ${maxNodes} reached` : 'Select all enabled agents'}
              >
                Select all
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-xs"
                onClick={onClear}
                disabled={selectedIds.size === 0}
              >
                None
              </button>
              <span className="ml-auto font-mono text-[10px] text-muted" aria-live="polite">
                {selectedIds.size} selected
                <span className="text-dim"> / {enabledCount} enabled</span>
              </span>
            </div>
            {atLimit ? (
              <p className="mt-1.5 text-[10px] leading-snug text-warn">
                Selection limit reached ({maxNodes}). Deselect an agent to choose another.
              </p>
            ) : null}
            {!atLimit && enabledCount > maxNodes ? (
              <p className="mt-1.5 text-[10px] leading-snug text-dim">
                Only {maxNodes} agents can run in one job; select the subset you need.
              </p>
            ) : null}
          </>
        ) : null}
      </div>
    </section>
  )
}
