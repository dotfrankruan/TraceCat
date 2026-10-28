import { useMemo } from 'react'
import type { Job } from '../api/types'
import type { JobLiveMode } from '../hooks/useJobLive'
import {
  absoluteTimestamp,
  formatDateTime,
  formatDurationMs,
  formatRtt,
  formatSeconds,
  relativeTime,
  shortId,
} from '../lib/format'
import { probeLabel } from '../lib/protocols'
import { isTerminalJob, jobStatusMeta, nodeStatusMeta } from '../lib/status'
import type { ViewMode } from '../types'
import { CompareView } from './CompareView'
import { IconDownload, IconHistory, IconNetwork } from './Icons'
import { NodeResultCard } from './NodeResultCard'
import { CopyButton, Skeleton, Spinner, StatusBadge } from './ui'

function jobDurationMs(job: Job): number | null {
  if (!job.started_at) return null
  const start = Date.parse(job.started_at)
  if (Number.isNaN(start)) return null
  const end = job.ended_at ? Date.parse(job.ended_at) : Date.now()
  if (Number.isNaN(end)) return null
  return Math.max(0, end - start)
}

function LiveBadge({ mode }: { mode: JobLiveMode }) {
  if (mode === 'idle') return null
  const label =
    mode === 'sse' ? 'live · SSE' : mode === 'polling' ? 'live · polling 3s' : 'live · connecting'
  const palette =
    mode === 'polling'
      ? 'border-warn/40 bg-warn/10 text-warn'
      : 'border-accent/40 bg-accent/10 text-accent'
  return (
    <span
      className={`badge ${palette}`}
      title="Job state changes are delivered as complete snapshots via SSE, with a 3s polling fallback. This is not hop-by-hop live streaming."
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${mode === 'polling' ? 'bg-warn' : 'bg-accent motion-safe:animate-pulse'}`}
        aria-hidden="true"
      />
      {label}
    </span>
  )
}

function Meta({ label, value, title }: { label: string; value: React.ReactNode; title?: string }) {
  return (
    <div className="min-w-0 px-2.5 py-1.5" title={title}>
      <p className="micro">{label}</p>
      <p className="mt-0.5 truncate font-mono text-[11px] text-fg-soft">{value}</p>
    </div>
  )
}

export function JobPanel({
  job,
  liveMode,
  view,
  onViewChange,
  onExport,
  exportBusy,
  onCopyJson,
  onJump,
  highlight,
  fromHistory,
}: {
  job: Job
  liveMode: JobLiveMode
  view: ViewMode
  onViewChange: (view: ViewMode) => void
  onExport: () => void
  exportBusy: boolean
  onCopyJson: () => void
  onJump: (nodeId: string, ttl: number) => void
  highlight: { nodeId: string; ttl: number } | null
  fromHistory: boolean
}) {
  const terminal = isTerminalJob(job.status)
  const statusMeta = jobStatusMeta(job.status)
  const duration = jobDurationMs(job)
  const target = job.original_target || job.target_ip
  const showResolved = job.original_target.length > 0 && job.original_target !== job.target_ip
  const summary = job.summary
  const reachedDestinations = useMemo(
    () => job.nodes.filter((node) => node.summary?.reached_destination === true).length,
    [job.nodes],
  )
  const terminalCount =
    summary.completed + summary.failed + summary.timed_out + summary.cancelled
  const pendingCount = summary.pending
  const runningCount = summary.running
  const statusCounts = [
    { label: 'pending', count: summary.pending, dot: 'bg-dim' },
    { label: 'running', count: summary.running, dot: 'bg-accent' },
    { label: 'completed', count: summary.completed, dot: 'bg-good' },
    { label: 'failed', count: summary.failed, dot: 'bg-bad' },
    { label: 'timed out', count: summary.timed_out, dot: 'bg-warn' },
    { label: 'cancelled', count: summary.cancelled, dot: 'bg-dim' },
  ].filter((entry) => entry.count > 0)

  return (
    <div className="space-y-3">
      <section className={`panel overflow-hidden border ${statusMeta.surface}`} aria-labelledby="job-heading">
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-line/70 px-3 py-2">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge meta={statusMeta} title={`Job status: ${statusMeta.label}`} />
              <span className="font-mono text-[10px] text-dim" title={job.id}>
                job {shortId(job.id, 10)}
              </span>
              <CopyButton value={job.id} label="Copy job id" />
              {fromHistory ? (
                <span className="badge badge-square border-line-strong bg-ink-800 text-muted">
                  <IconHistory className="h-2.5 w-2.5" />
                  stored job
                </span>
              ) : null}
              <LiveBadge mode={liveMode} />
              <span
                className="badge badge-square border-accent/35 bg-accent/10 text-accent"
                title="Probe protocol and destination port"
              >
                {probeLabel(job.protocol, job.port)}
              </span>
            </div>
            <h2
              id="job-heading"
              className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[15px] font-semibold leading-tight text-fg"
            >
              <span className="break-all">{target}</span>
              {showResolved ? (
                <span className="font-mono text-[11px] font-normal text-muted">
                  traced {job.target_ip}
                </span>
              ) : null}
            </h2>
            <p className="mt-0.5 flex flex-wrap items-center gap-x-2 font-mono text-[10px] text-dim">
              <span title={absoluteTimestamp(job.created_at)}>
                created {formatDateTime(job.created_at)} ({relativeTime(job.created_at)})
              </span>
              {job.created_by ? (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="truncate" title={job.created_by}>
                    by {job.created_by}
                  </span>
                </>
              ) : null}
            </p>
          </div>

          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={onExport}
              disabled={exportBusy}
              aria-label="Export job as JSON"
              title="Download the full job export (includes bounded raw results)"
            >
              {exportBusy ? (
                <Spinner className="h-3 w-3" />
              ) : (
                <IconDownload className="h-3 w-3" />
              )}
              <span className="hidden sm:inline">Export JSON</span>
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={onCopyJson}
              title="Copy this job document to the clipboard"
            >
              copy JSON
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-px border-b border-line/60 bg-line/40 sm:grid-cols-4 xl:grid-cols-8">
          <Meta label="Family" value={job.family} />
          <Meta
            label="Protocol"
            value={probeLabel(job.protocol, job.port)}
            title="Probe protocol and destination port (port applies to TCP/UDP only)"
          />
          <Meta label="Max hops" value={job.max_hops} />
          <Meta label="Queries" value={`${job.queries}×`} />
          <Meta label="Timeout" value={formatSeconds(job.timeout_ms)} />
          <Meta label="Duration" value={formatDurationMs(duration)} />
          <Meta
            label="Dest. reached"
            value={`${summary.reached}/${summary.total}`}
            title="Nodes that observed a reply from the exact destination IP"
          />
          <Meta label="Dest. latency" value={
            summary.reached > 0 ? (
              <span>
                {formatRtt(
                  job.nodes
                    .map((node) => node.summary?.destination_rtt_ms)
                    .filter((value): value is number => value != null)
                    .sort((left, right) => left - right)[0],
                )}{' '}
                ms
              </span>
            ) : (
              '—'
            )
          } title="Fastest destination RTT across nodes" />
        </div>

        <div className="px-3 py-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="micro">Node progress</p>
            <p className="font-mono text-[10px] text-muted">
              {terminalCount}/{summary.total} terminal
              {reachedDestinations > 0 ? (
                <span className="text-good"> · {reachedDestinations} reached destination</span>
              ) : null}
            </p>
          </div>

          <div
            className="mt-1.5 flex gap-0.5 overflow-hidden rounded-full"
            role="img"
            aria-label={`Node status: ${statusCounts.map((entry) => `${entry.count} ${entry.label}`).join(', ') || 'no nodes'}`}
          >
            {job.nodes.map((node) => {
              const meta = nodeStatusMeta(node.status)
              return (
                <span
                  key={node.node_id}
                  className={`h-1.5 flex-1 rounded-full ${meta.dot} ${node.status === 'pending' ? 'opacity-40' : ''}`}
                  title={`${node.node_name}: ${meta.label}`}
                />
              )
            })}
          </div>

          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[9px] uppercase tracking-wider text-dim">
            {statusCounts.map((entry) => (
              <span key={entry.label} className="inline-flex items-center gap-1">
                <span className={`h-1.5 w-1.5 rounded-full ${entry.dot}`} aria-hidden="true" />
                {entry.count} {entry.label}
              </span>
            ))}
            {pendingCount + runningCount > 0 ? (
              <span className="ml-auto normal-case tracking-normal text-dim">
                waiting on {pendingCount + runningCount} node{pendingCount + runningCount === 1 ? '' : 's'}
              </span>
            ) : null}
          </div>

          <ul className="mt-2 flex flex-wrap gap-1">
            {job.nodes.map((node) => {
              const meta = nodeStatusMeta(node.status)
              return (
                <li key={node.node_id}>
                  <span
                    className="inline-flex max-w-[16rem] items-center gap-1.5 rounded border border-line bg-ink-950/50 px-1.5 py-0.5"
                    title={`${node.node_name}${node.location ? ` · ${node.location}` : ''} — ${meta.label}`}
                  >
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${meta.dot}`} aria-hidden="true" />
                    <span className="truncate text-[10px] text-fg-soft">{node.node_name}</span>
                    <span className={`badge badge-square ${meta.badge}`}>{meta.label}</span>
                    {node.duration_ms != null ? (
                      <span className="font-mono text-[9px] text-dim">
                        {formatDurationMs(node.duration_ms)}
                      </span>
                    ) : null}
                  </span>
                </li>
              )
            })}
          </ul>

          {!terminal ? (
            <p className="mt-2 flex items-start gap-1.5 border-t border-line/60 pt-1.5 text-[10px] leading-snug text-dim">
              <IconNetwork className="mt-0.5 h-3 w-3 shrink-0" />
              Updates are state-change notifications with full job snapshots (SSE, polling fallback).
              Hops appear when an agent reports its complete result — not as live per-hop streaming.
            </p>
          ) : null}
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <div
          className="inline-flex rounded border border-line bg-ink-900/90 p-0.5"
          role="group"
          aria-label="Result view"
        >
          <button
            type="button"
            className={`rounded px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
              view === 'detailed'
                ? 'bg-ink-750 text-fg'
                : 'text-muted hover:bg-white/[0.04] hover:text-fg'
            }`}
            aria-pressed={view === 'detailed'}
            onClick={() => onViewChange('detailed')}
          >
            Detailed
          </button>
          <button
            type="button"
            className={`rounded px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
              view === 'compare'
                ? 'bg-ink-750 text-fg'
                : 'text-muted hover:bg-white/[0.04] hover:text-fg'
            }`}
            aria-pressed={view === 'compare'}
            onClick={() => onViewChange('compare')}
          >
            Compare
          </button>
        </div>
        <p className="font-mono text-[10px] text-dim">
          {job.nodes.length} node{job.nodes.length === 1 ? '' : 's'} ·{' '}
          {terminal ? 'final snapshots' : 'updates in progress'}
        </p>
      </div>

      {view === 'detailed' ? (
        <div className="space-y-3">
          {job.nodes.map((node) => (
            <NodeResultCard
              key={node.node_id}
              node={node}
              targetIP={job.target_ip}
              protocol={job.protocol}
              port={job.port}
              highlightedTtl={
                highlight && highlight.nodeId === node.node_id ? highlight.ttl : null
              }
              onJump={onJump}
            />
          ))}
        </div>
      ) : (
        <CompareView job={job} onJump={onJump} />
      )}

      <details className="panel px-3 py-2">
        <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-dim hover:text-fg">
          Raw job JSON (debug)
        </summary>
        <pre className="mt-2 max-h-64 overflow-auto break-all rounded bg-ink-950 p-2 font-mono text-[10px] leading-relaxed text-muted">
          {JSON.stringify(job, null, 2)}
        </pre>
      </details>
    </div>
  )
}

export function JobPanelSkeleton() {
  return (
    <div className="panel space-y-2 px-3 py-3" aria-busy="true" aria-label="Loading stored job">
      <Skeleton className="h-5 w-2/3" />
      <Skeleton className="h-3 w-1/3" />
      <div className="grid grid-cols-2 gap-2 pt-2 sm:grid-cols-4">
        {Array.from({ length: 8 }, (_, index) => (
          <Skeleton key={index} className="h-9 w-full" />
        ))}
      </div>
    </div>
  )
}
