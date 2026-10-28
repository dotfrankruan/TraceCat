import { Fragment, useMemo } from 'react'
import type { HopView } from '../lib/hops'
import { answerKey } from '../lib/hops'
import { asnChipClass, asnToneClass } from '../lib/asn'

/**
 * Wrapped AS-path chip strip for one node. Chips are TTL-addressable buttons
 * that highlight and scroll to the matching hop table row. Network/ASN
 * transitions are marked with a caret; "no reply" hops stay visibly neutral and
 * are never styled as failures.
 */
export function AsPath({
  nodeId,
  nodeName,
  views,
  highlightedTtl,
  onJump,
}: {
  nodeId: string
  nodeName: string
  views: HopView[]
  highlightedTtl: number | null
  onJump: (nodeId: string, ttl: number) => void
}) {
  const items = useMemo(() => {
    let previousKey: string | null = null
    return views.map((view) => {
      const key = answerKey(view)
      const transition = key !== null && previousKey !== null && key !== previousKey
      if (key !== null) previousKey = key
      return { view, key, transition }
    })
  }, [views])

  if (items.length === 0) return null

  return (
    <div className="mt-1">
      <div className="flex items-center justify-between gap-2">
        <span className="micro">AS path</span>
        <span className="font-mono text-[9px] uppercase tracking-wider text-dim">
          TTL → network
        </span>
      </div>
      <ol
        className="mt-1.5 flex flex-wrap items-center gap-x-1 gap-y-1.5"
        aria-label={`AS path from ${nodeName}`}
      >
        {items.map(({ view, transition }) => {
          const active = highlightedTtl === view.ttl
          const label = view.noReply
            ? `TTL ${view.ttl}: no reply`
            : `TTL ${view.ttl}: ${view.asn != null ? `AS${view.asn}` : view.asName || 'reply'}${
                view.asName ? ` ${view.asName}` : ''
              }${view.minRttMs != null ? `, ${view.minRttMs.toFixed(1)} ms` : ''}`
          const suffix = transition ? ', network/ASN change' : ''
          return (
            <li key={view.ttl} className="flex items-center gap-0.5">
              {transition ? (
                <span
                  className="px-0.5 font-mono text-[9px] text-warn/80"
                  aria-hidden="true"
                  title="Network/ASN change"
                >
                  ▸
                </span>
              ) : null}
              <button
                type="button"
                onClick={() => onJump(nodeId, view.ttl)}
                aria-label={`${label}${suffix}. Show hop row.`}
                title={`${label}${suffix} — click to show this hop`}
                className={`flex items-center gap-1 rounded border px-1 py-0.5 text-[10px] transition-colors ${
                  active
                    ? 'border-accent/70 bg-accent/10'
                    : view.noReply
                      ? 'border-dashed border-line-strong bg-transparent hover:border-dim'
                      : `border-line bg-ink-950/50 hover:bg-ink-800 ${asnToneClass(view.asnKey)}`
                }`}
              >
                <span className="font-mono tabular-nums text-dim">{view.ttl}</span>
                {view.noReply ? (
                  <span className="text-muted">no reply</span>
                ) : (
                  <>
                    {view.asn != null || view.asName ? (
                      <span className={`asn-chip border-0 bg-transparent px-0 py-0 ${asnChipClass(view.asnKey)}`}>
                        {view.asn != null ? `AS${view.asn}` : view.asName}
                      </span>
                    ) : (
                      <span className="font-mono text-muted">{view.primary?.address ?? 'reply'}</span>
                    )}
                    {view.asName && view.asn != null ? (
                      <span
                        className="max-w-[8.5rem] truncate text-dim"
                        title={view.asName}
                      >
                        {view.asName}
                      </span>
                    ) : view.geo ? (
                      <span className="max-w-[8.5rem] truncate text-dim" title={view.geo}>
                        {view.geo}
                      </span>
                    ) : null}
                  </>
                )}
              </button>
            </li>
          )
        })}
      </ol>
      <p className="mt-1 text-[9px] leading-snug text-dim">
        <span aria-hidden="true" className="text-warn/80">
          ▸
        </span>{' '}
        marks a network/ASN transition. Dashed “no reply” hops are unanswered probes, not
        confirmed failures.
      </p>
    </div>
  )
}

/** Compact chip strip used in the compare columns. */
export function ComparePathChips({
  nodeId,
  nodeName,
  views,
  onJump,
}: {
  nodeId: string
  nodeName: string
  views: HopView[]
  onJump: (nodeId: string, ttl: number) => void
}) {
  if (views.length === 0) {
    return <p className="text-[10px] text-dim">No path reported yet.</p>
  }
  return (
    <ol className="flex flex-wrap gap-0.5" aria-label={`AS path from ${nodeName}`}>
      {views.map((view) => (
        <Fragment key={view.ttl}>
          <li>
            <button
              type="button"
              onClick={() => onJump(nodeId, view.ttl)}
              className={`rounded border px-1 py-0.5 font-mono text-[9px] leading-none transition-colors ${
                view.noReply
                  ? 'border-dashed border-line-strong text-muted hover:border-dim'
                  : `${asnChipClass(view.asnKey)} hover:brightness-125`
              }`}
              title={
                view.noReply
                  ? `TTL ${view.ttl}: no reply`
                  : `TTL ${view.ttl}: ${view.asn != null ? `AS${view.asn}` : view.asName || view.primary?.address}`
              }
              aria-label={
                view.noReply
                  ? `TTL ${view.ttl}: no reply. Open detailed view.`
                  : `TTL ${view.ttl}: ${view.asn != null ? `AS${view.asn}` : view.asName || 'reply'}. Open detailed view.`
              }
            >
              {view.ttl}
              {view.noReply ? '·–' : view.asn != null ? `·${view.asn}` : '·'}
            </button>
          </li>
        </Fragment>
      ))}
    </ol>
  )
}
