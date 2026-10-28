import { useId } from 'react'
import type { ControllerLimits } from '../api/types'
import { formatSeconds, pluralize } from '../lib/format'
import type { JobStatus } from '../api/types'
import { jobStatusMeta } from '../lib/status'
import { IconPlay, IconStop } from './Icons'
import { Spinner } from './ui'

function ParameterRange({
  label,
  hint,
  value,
  min,
  max,
  step,
  display,
  onChange,
  disabled,
}: {
  label: string
  hint: string
  value: number
  min: number
  max: number
  step: number
  display: string
  onChange: (value: number) => void
  disabled?: boolean
}) {
  const id = useId()
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2">
        <label htmlFor={id} className="text-[11px] text-fg-soft">
          {label}
        </label>
        <output
          htmlFor={id}
          className="font-mono text-[11px] tabular-nums text-accent"
          aria-live="off"
        >
          {display}
        </output>
      </div>
      <input
        id={id}
        type="range"
        className="mt-1 h-1.5 w-full cursor-pointer accent-accent"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled || min >= max}
        onChange={(event) => onChange(Number(event.target.value))}
      />
      <p className="mt-0.5 text-[10px] leading-snug text-dim">{hint}</p>
    </div>
  )
}

export function RunPanel({
  limits,
  maxHops,
  queries,
  timeoutMs,
  onMaxHops,
  onQueries,
  onTimeout,
  destination,
  selectedNodeCount,
  startBlockReason,
  startBusy,
  onStart,
  activeJobId,
  activeJobStatus,
  cancelBusy,
  onCancel,
}: {
  limits: ControllerLimits
  maxHops: number
  queries: number
  timeoutMs: number
  onMaxHops: (value: number) => void
  onQueries: (value: number) => void
  onTimeout: (value: number) => void
  destination: string | null
  selectedNodeCount: number
  startBlockReason: string | null
  startBusy: boolean
  onStart: () => void
  activeJobId: string | null
  activeJobStatus: JobStatus | null
  cancelBusy: boolean
  onCancel: () => void
}) {
  const timeoutMin = Math.min(limits.min_execution_ms, limits.max_execution_ms)
  const timeoutMax = Math.max(limits.min_execution_ms, limits.max_execution_ms)
  const reasonId = useId()
  const canStart = startBlockReason === null && !startBusy
  const activeNonTerminal =
    activeJobId !== null &&
    activeJobStatus !== null &&
    activeJobStatus !== 'completed' &&
    activeJobStatus !== 'partial' &&
    activeJobStatus !== 'failed' &&
    activeJobStatus !== 'cancelled'
  const statusMeta = activeJobStatus ? jobStatusMeta(activeJobStatus) : null

  return (
    <section className="panel" aria-labelledby="run-heading">
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-3 py-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] leading-none text-accent/80">03</span>
            <h2
              id="run-heading"
              className="font-mono text-[11px] font-semibold uppercase leading-none tracking-[0.16em] text-fg-soft"
            >
              Trace parameters
            </h2>
          </div>
          <p className="mt-1 text-[11px] text-muted">
            Server limits are authoritative and enforced again on submit
          </p>
        </div>
        <span className="badge badge-square border-line-strong text-muted" title="Probe protocol">
          icmp
        </span>
      </header>

      <div className="px-3 py-2.5">
        <fieldset className="space-y-2.5">
          <legend className="sr-only">Trace execution parameters</legend>
          <ParameterRange
            label="Max hops"
            hint={`TTL ceiling · server allows 1–${limits.max_hops}`}
            value={maxHops}
            min={1}
            max={Math.max(1, limits.max_hops)}
            step={1}
            display={`${maxHops} hops`}
            onChange={onMaxHops}
            disabled={startBusy}
          />
          <ParameterRange
            label="Queries per hop"
            hint={`Probes per TTL · server allows 1–${limits.max_queries}`}
            value={queries}
            min={1}
            max={Math.max(1, limits.max_queries)}
            step={1}
            display={`${queries}×`}
            onChange={onQueries}
            disabled={startBusy}
          />
          <ParameterRange
            label="Execution timeout"
            hint={`Bounds the whole trace on each agent · ${formatSeconds(timeoutMin)}–${formatSeconds(timeoutMax)}`}
            value={timeoutMs}
            min={timeoutMin}
            max={timeoutMax}
            step={1000}
            display={formatSeconds(timeoutMs)}
            onChange={onTimeout}
            disabled={startBusy}
          />
        </fieldset>

        <div className="mt-3 rounded border border-line bg-ink-950/60 px-2 py-1.5">
          <p className="micro">Request</p>
          <p className="mt-0.5 break-all font-mono text-[11px] text-fg-soft">
            {destination ?? 'no destination selected'}
          </p>
          <p className="mt-0.5 text-[10px] text-muted">
            {selectedNodeCount} {pluralize(selectedNodeCount, 'agent')} · {maxHops} hops ·{' '}
            {queries} queries · {formatSeconds(timeoutMs)}
          </p>
        </div>

        <div className="mt-3 space-y-1.5">
          <button
            type="button"
            className="btn btn-primary w-full"
            onClick={onStart}
            disabled={!canStart}
            aria-describedby={startBlockReason ? reasonId : undefined}
          >
            {startBusy ? <Spinner className="h-3.5 w-3.5" /> : <IconPlay className="h-3.5 w-3.5" />}
            {startBusy ? 'Starting trace…' : 'Start trace'}
          </button>
          {startBlockReason ? (
            <p id={reasonId} className="text-center text-[10px] leading-snug text-muted">
              {startBlockReason}
            </p>
          ) : (
            <p className="text-center text-[10px] leading-snug text-dim">
              Dispatches one ICMP trace per selected agent.
            </p>
          )}

          {activeNonTerminal && activeJobId ? (
            <div className="border-t border-line/70 pt-2">
              <div className="mb-1.5 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 font-mono text-[10px] text-muted">
                  <span className={`h-1.5 w-1.5 rounded-full ${statusMeta?.dot ?? 'bg-dim'}`} />
                  active job
                </span>
                <span className="font-mono text-[10px] text-dim">{activeJobId.slice(0, 8)}…</span>
              </div>
              <button
                type="button"
                className="btn btn-danger w-full"
                onClick={onCancel}
                disabled={cancelBusy}
              >
                {cancelBusy ? <Spinner className="h-3.5 w-3.5" /> : <IconStop className="h-3 w-3" />}
                {cancelBusy ? 'Cancelling…' : 'Cancel job'}
              </button>
            </div>
          ) : null}
        </div>

        <p className="mt-2.5 border-t border-line/70 pt-2 text-[10px] leading-snug text-dim">
          TraceCat never retries silently. Timeout applies to the entire execution, not one probe;
          a router that ignores a probe is shown as “no reply”, not as a failure.
        </p>
      </div>
    </section>
  )
}
