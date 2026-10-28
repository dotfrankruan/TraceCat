import type { ApiError } from '../api/client'
import type { JobListItem, JobStatus } from '../api/types'
import {
  absoluteTimestamp,
  formatDateTime,
  relativeTime,
} from '../lib/format'
import { jobStatusMeta } from '../lib/status'
import { IconHistory, IconRefresh } from './Icons'
import { EmptyState, ErrorNote, Skeleton, Spinner } from './ui'

function reachedFor(job: JobListItem): number {
  return job.summary?.reached ?? 0
}

function totalFor(job: JobListItem): number {
  return job.summary?.total ?? 0
}

function statusDotClass(status: JobStatus | string): string {
  return jobStatusMeta(status).dot
}

export function HistoryPanel({
  jobs,
  loading,
  error,
  activeJobId,
  onOpen,
  onRefresh,
  limit,
}: {
  jobs: JobListItem[]
  loading: boolean
  error: ApiError | null
  activeJobId: string | null
  onOpen: (id: string) => void
  onRefresh: () => void
  limit: number
}) {
  return (
    <section
      id="history"
      className="panel scroll-mt-20"
      aria-labelledby="history-heading"
    >
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-3 py-2">
        <div>
          <div className="flex items-center gap-2">
            <IconHistory className="h-3.5 w-3.5 text-accent/80" />
            <h2
              id="history-heading"
              className="font-mono text-[11px] font-semibold uppercase leading-none tracking-[0.16em] text-fg-soft"
            >
              History
            </h2>
          </div>
          <p className="mt-1 text-[11px] text-muted">
            Newest first · stored by the controller
          </p>
        </div>
        <button
          type="button"
          className="btn btn-ghost btn-xs shrink-0"
          onClick={onRefresh}
          disabled={loading}
          aria-label="Refresh job history"
          title="Refresh history"
        >
          {loading ? <Spinner className="h-3 w-3" /> : <IconRefresh className="h-3 w-3" />}
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </header>

      <div className="py-1.5">
        {loading && jobs.length === 0 ? (
          <div className="space-y-1 px-3 py-1.5" aria-hidden="true">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-9 w-full" />
          </div>
        ) : null}

        {error ? (
          <div className="px-3 py-1.5">
            <ErrorNote error={error} onRetry={onRefresh} compact />
          </div>
        ) : null}

        {!loading && !error && jobs.length === 0 ? (
          <div className="px-3">
            <EmptyState title="No stored traces" icon={<IconHistory className="h-5 w-5" />}>
              Completed and failed jobs are listed here, bounded by the controller’s history
              setting. Start a trace to populate it.
            </EmptyState>
          </div>
        ) : null}

        {jobs.length > 0 ? (
          <ul className="divide-y divide-line/50">
            {jobs.map((job) => {
              const active = activeJobId === job.id
              const reached = reachedFor(job)
              const total = totalFor(job)
              const target = job.original_target || job.target_ip
              const meta = jobStatusMeta(job.status)
              return (
                <li key={job.id}>
                  <button
                    type="button"
                    onClick={() => onOpen(job.id)}
                    aria-current={active ? 'true' : undefined}
                    className={`flex w-full items-start gap-2 px-3 py-1.5 text-left transition-colors ${
                      active
                        ? 'border-l-2 border-l-accent bg-accent/[0.06] pl-[10px]'
                        : 'border-l-2 border-l-transparent hover:bg-white/[0.025]'
                    }`}
                  >
                    <span
                      className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${statusDotClass(job.status)}`}
                      aria-hidden="true"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline justify-between gap-2">
                        <span
                          className="min-w-0 truncate font-mono text-[11px] text-fg"
                          title={target}
                        >
                          {target}
                        </span>
                        <time
                          className="shrink-0 font-mono text-[9px] text-dim"
                          dateTime={job.created_at}
                          title={absoluteTimestamp(job.created_at)}
                        >
                          {relativeTime(job.created_at)}
                        </time>
                      </span>
                      <span className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[9px] text-muted">
                        <span className={`badge badge-square ${meta.badge}`}>{meta.label}</span>
                        <span
                          className="break-all font-mono text-dim"
                          title={formatDateTime(job.created_at)}
                        >
                          {job.target_ip}
                        </span>
                        <span aria-hidden="true" className="text-dim">
                          ·
                        </span>
                        <span>
                          {total} node{total === 1 ? '' : 's'}
                        </span>
                        <span aria-hidden="true" className="text-dim">
                          ·
                        </span>
                        <span className={reached > 0 ? 'text-good' : 'text-dim'}>
                          {reached}/{total} reached
                        </span>
                      </span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        ) : null}
      </div>

      <footer className="flex items-center justify-between border-t border-line/70 px-3 py-1.5">
        <span className="font-mono text-[9px] uppercase tracking-wider text-dim">
          latest {Math.min(jobs.length, limit)} · limit {limit}
        </span>
        <span className="font-mono text-[9px] text-dim">click to open</span>
      </footer>
    </section>
  )
}
