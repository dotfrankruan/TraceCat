import { Fragment, useMemo } from 'react'
import type { Job, NodeResult } from '../api/types'
import { asnChipClass, asnToneClass } from '../lib/asn'
import {
  answerKey,
  asnPathForNode,
  buildPath,
  destinationObserved,
  destinationRttMs,
  findHopByTtl,
  maxObservedTtl,
  replyStats,
  type HopView,
} from '../lib/hops'
import { formatRtt } from '../lib/format'
import { probeLabel } from '../lib/protocols'
import { nodeStatusMeta } from '../lib/status'
import { ComparePathChips } from './AsPath'
import { IconAlert, IconNetwork } from './Icons'
import { EmptyState, InfoNote, StatusBadge } from './ui'

function hopSignature(hop: HopView | null): string {
  if (!hop) return 'absent'
  if (hop.noReply) return 'no-reply'
  return answerKey(hop) ?? hop.primary?.address ?? 'reply'
}

function pathColumns(job: Job): Array<{ node: NodeResult; path: HopView[] }> {
  return job.nodes.map((node) => ({ node, path: buildPath(node.hops) }))
}

function CompareMetric({
  label,
  divergent,
  children,
  note,
  icon,
}: {
  label: string
  divergent: boolean
  children: React.ReactNode
  note: React.ReactNode
  icon?: React.ReactNode
}) {
  return (
    <div
      className={`rounded border px-2.5 py-2 ${
        divergent ? 'border-warn/35 bg-warn/[0.04]' : 'border-line bg-ink-950/40'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="micro flex items-center gap-1.5">
          {icon}
          {label}
        </p>
        {divergent ? (
          <span className="badge badge-square border-warn/40 bg-warn/10 text-warn">differs</span>
        ) : (
          <span className="font-mono text-[9px] uppercase tracking-wider text-dim">aligned</span>
        )}
      </div>
      <div className="mt-1.5">{children}</div>
      <p className="mt-1.5 border-t border-line/60 pt-1.5 text-[10px] leading-snug text-dim">
        {note}
      </p>
    </div>
  )
}

function NodeMetricList({ rows }: { rows: Array<{ name: string; value: React.ReactNode }> }) {
  return (
    <ul className="space-y-0.5">
      {rows.map((row) => (
        <li key={row.name} className="flex items-baseline justify-between gap-2">
          <span className="min-w-0 truncate text-[11px] text-muted">{row.name}</span>
          <span className="shrink-0 font-mono text-[11px] text-fg-soft">{row.value}</span>
        </li>
      ))}
    </ul>
  )
}

export function CompareView({
  job,
  onJump,
}: {
  job: Job
  onJump: (nodeId: string, ttl: number) => void
}) {
  const columns = useMemo(() => pathColumns(job), [job])
  const maxTtl = useMemo(() => maxObservedTtl(job.nodes), [job.nodes])
  const ttls = useMemo(
    () => Array.from({ length: maxTtl }, (_, index) => index + 1),
    [maxTtl],
  )

  if (job.nodes.length < 2) {
    return (
      <section className="panel" aria-labelledby="compare-needs-more">
        <div className="px-3 py-3">
          <EmptyState
            title="Comparison needs at least 2 agents"
            icon={<IconNetwork className="h-5 w-5" />}
          >
            This job ran on {job.nodes.length} agent{job.nodes.length === 1 ? '' : 's'}. Select two
            or more agents in step 02, then start the trace again to compare paths side by side.
            Side-by-side differences are only meaningful across multiple vantage points.
          </EmptyState>
          <p className="mt-1 font-mono text-[10px] text-dim" id="compare-needs-more">
            {job.nodes.map((node) => node.node_name).join(' · ')}
          </p>
        </div>
      </section>
    )
  }

  const hopCounts = columns.map(({ node }) => ({
    node,
    count: node.summary?.hop_count ?? (node.hops?.length ?? 0),
  }))
  const hopCountDiverges = new Set(hopCounts.map((entry) => entry.count)).size > 1

  const asnPaths = columns.map(({ node }) => ({ node, ...asnPathForNode(node) }))
  const asnSequenceDiverges =
    new Set(asnPaths.map((entry) => entry.sequence.join('→'))).size > 1

  const observedRows = columns.map(({ node }) => ({
    node,
    observed: destinationObserved(node),
    rtt: destinationRttMs(node),
  }))
  const observationDiverges = new Set(observedRows.map((entry) => entry.observed)).size > 1
  const observedCount = observedRows.filter((entry) => entry.observed).length
  const observedRtts = observedRows
    .filter((entry): entry is typeof entry & { rtt: number } => entry.rtt != null)
    .sort((left, right) => left.rtt - right.rtt)
  const fastest = observedRtts[0]
  const slowest = observedRtts[observedRtts.length - 1]
  const latencyDelta =
    fastest && slowest && observedRtts.length >= 2 ? slowest.rtt - fastest.rtt : null

  const replyRows = columns.map(({ node }) => ({ node, stats: replyStats(node) }))
  const nodeErrors = job.nodes.filter((node) => node.error)

  return (
    <div className="space-y-3">
      <InfoNote tone="info" title="How to read this comparison">
        Paths are aligned by TTL and compared as observations. Only destination observation and
        agent-reported errors are conclusion-worthy; an unanswered intermediate probe is common and
        is never shown as a failure. No silent retries are performed.
      </InfoNote>

      {maxTtl === 0 ? (
        <section className="panel px-3 py-3">
          <p className="font-mono text-[11px] uppercase tracking-wider text-muted">
            No hop data yet
          </p>
          <p className="mt-1 text-[12px] text-dim">
            The agents have not reported any hops. Node statuses:{' '}
            {job.nodes
              .map((node) => `${node.node_name} (${nodeStatusMeta(node.status).label})`)
              .join(', ')}
            .
          </p>
        </section>
      ) : (
        <section className="panel overflow-hidden" aria-labelledby="compare-path-heading">
          <header className="flex items-center justify-between gap-2 border-b border-line/70 px-3 py-2">
            <h3
              id="compare-path-heading"
              className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-fg-soft"
            >
              Aligned paths
            </h3>
            <span className="font-mono text-[10px] text-dim">
              {probeLabel(job.protocol, job.port)} · {ttls.length} observed TTL
              {ttls.length === 1 ? '' : 's'}
            </span>
          </header>
          <div className="table-scroll">
            <table className="w-full min-w-[640px] border-collapse text-left">
              <caption className="sr-only">
                Side-by-side hop comparison for {columns.map(({ node }) => node.node_name).join(', ')}.
                Rows marked as differing are observations, not failures.
              </caption>
              <thead>
                <tr className="border-b border-line bg-ink-850/70">
                  <th
                    scope="col"
                    className="w-14 bg-ink-850/90 px-2 py-2 font-mono text-[9px] font-medium uppercase tracking-wider text-dim"
                  >
                    TTL
                  </th>
                  {columns.map(({ node, path }) => (
                    <th
                      key={node.node_id}
                      scope="col"
                      className="min-w-[200px] border-l border-line/60 px-2 py-2 align-top font-normal"
                    >
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[12px] font-semibold text-fg">{node.node_name}</span>
                        <StatusBadge meta={nodeStatusMeta(node.status)} />
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10px] text-muted">
                        <span>
                          {destinationObserved(node) ? (
                            <span className="text-good">dest observed</span>
                          ) : (
                            <span className="text-muted">dest not observed</span>
                          )}
                        </span>
                        {destinationRttMs(node) != null ? (
                          <span className="tabular-nums">
                            {formatRtt(destinationRttMs(node))} ms
                          </span>
                        ) : null}
                        <span className="text-dim">
                          {replyStats(node).replies}/{replyStats(node).probes} replies
                        </span>
                      </div>
                      <div className="mt-1">
                        <ComparePathChips
                          nodeId={node.node_id}
                          nodeName={node.node_name}
                          views={path}
                          onJump={onJump}
                        />
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ttls.map((ttl) => {
                  const rowHops = columns.map(({ node }) => findHopByTtl(node.hops, ttl))
                  const signatures = rowHops.map(hopSignature)
                  const divergent = new Set(signatures).size > 1
                  return (
                    <tr
                      key={ttl}
                      className={`border-t border-line/50 ${
                        divergent ? 'bg-warn/[0.045]' : 'hover:bg-white/[0.02]'
                      }`}
                    >
                      <th
                        scope="row"
                        className="sticky left-0 bg-ink-900/95 px-2 py-1.5 align-top text-left font-mono text-[11px] font-normal tabular-nums text-muted"
                      >
                        {ttl}
                        {divergent ? (
                          <>
                            <span className="ml-1 text-warn" aria-hidden="true">
                              ≠
                            </span>
                            <span className="sr-only">paths differ at this TTL</span>
                          </>
                        ) : null}
                      </th>
                      {rowHops.map((hop, index) => {
                        const node = columns[index]?.node
                        if (!node) return null
                        return (
                          <td
                            key={node.node_id}
                            className="border-l border-line/50 px-2 py-1.5 align-top"
                          >
                            {hop == null ? (
                              <span
                                className="font-mono text-[11px] text-dim"
                                title="No hop was observed at this TTL; the path may be shorter."
                              >
                                —
                              </span>
                            ) : hop.noReply ? (
                              <span
                                className="inline-flex rounded border border-dashed border-line-strong px-1 py-0.5 text-[10px] text-muted"
                                title="No reply at this TTL. Intermediate routers often drop probes; not a failure."
                              >
                                no reply
                              </span>
                            ) : (
                              <div className="flex flex-wrap items-center gap-1">
                                <span
                                  className="break-all font-mono text-[11px] text-fg-soft"
                                  title={hop.addresses.join(', ')}
                                >
                                  {hop.primary?.address ?? 'reply'}
                                </span>
                                {hop.asn != null || hop.asName ? (
                                  <span
                                    className={`asn-chip ${asnChipClass(hop.asnKey)}`}
                                    title={hop.asName || 'Autonomous system'}
                                  >
                                    {hop.asn != null ? `AS${hop.asn}` : hop.asName}
                                  </span>
                                ) : null}
                                {hop.minRttMs != null ? (
                                  <span className="font-mono text-[10px] tabular-nums text-dim">
                                    {formatRtt(hop.minRttMs)} ms
                                  </span>
                                ) : null}
                              </div>
                            )}
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <p className="border-t border-line/60 px-3 py-1.5 text-[9px] leading-snug text-dim">
            Rows tinted amber contain divergent observations between nodes. “—” means no hop was
            observed at that TTL, not a failed hop.
          </p>
        </section>
      )}

      <section className="panel" aria-labelledby="compare-diff-heading">
        <header className="flex items-center justify-between gap-2 border-b border-line/70 px-3 py-2">
          <h3
            id="compare-diff-heading"
            className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-fg-soft"
          >
            Computed differences
          </h3>
          <span className="font-mono text-[10px] text-dim">honest deltas only</span>
        </header>
        <div className="grid grid-cols-1 gap-2 px-3 py-2.5 sm:grid-cols-2">
          <CompareMetric
            label="Hop count"
            divergent={hopCountDiverges}
            icon={<IconNetwork className="h-3 w-3" />}
            note={
              hopCountDiverges
                ? 'Observed hop counts differ. No-reply hops can change how many TTLs are visible; this is not a success/failure verdict.'
                : 'All nodes observed the same number of hops.'
            }
          >
            <NodeMetricList
              rows={hopCounts.map(({ node, count }) => ({
                name: node.node_name,
                value: `${count} hop${count === 1 ? '' : 's'}`,
              }))}
            />
          </CompareMetric>

          <CompareMetric
            label="ASN transitions"
            divergent={asnSequenceDiverges}
            icon={<IconNetwork className="h-3 w-3" />}
            note={
              asnSequenceDiverges
                ? 'The paths traverse different network sequences. Unanswered hops are skipped rather than treated as transitions.'
                : 'The observed AS sequences match on every node.'
            }
          >
            <ul className="space-y-1.5">
              {asnPaths.map(({ node, sequence, transitions }) => (
                <li key={node.node_id}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="truncate text-[11px] text-muted">{node.node_name}</span>
                    <span className="shrink-0 font-mono text-[10px] text-dim">
                      {transitions} transition{transitions === 1 ? '' : 's'}
                    </span>
                  </div>
                  {sequence.length > 0 ? (
                    <div className="mt-0.5 flex flex-wrap items-center gap-0.5">
                      {sequence.map((key, index) => (
                        <Fragment key={`${key}-${index}`}>
                          {index > 0 ? (
                            <span className="font-mono text-[9px] text-dim" aria-hidden="true">
                              →
                            </span>
                          ) : null}
                          <span
                            className={`asn-chip ${asnToneClass(key)}`}
                            title={key}
                          >
                            {key}
                          </span>
                        </Fragment>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-0.5 text-[10px] text-dim">no answered hops</p>
                  )}
                </li>
              ))}
            </ul>
          </CompareMetric>

          <CompareMetric
            label="Destination observation"
            divergent={observationDiverges}
            icon={<IconAlert className="h-3 w-3" />}
            note={
              observationDiverges
                ? 'The destination IP was observed by some nodes but not others. This can reflect ICMP filtering, rate limiting or timeout at the destination; it does not by itself prove a broken path, and intermediate no-replies must not be read as failures.'
                : observedCount === job.nodes.length
                  ? 'Every node observed a reply from the exact destination IP.'
                  : 'No node observed the destination within its trace window. That is an observation gap, not proof of unreachability.'
            }
          >
            <NodeMetricList
              rows={observedRows.map(({ node, observed }) => ({
                name: node.node_name,
                value: observed ? (
                  <span className="text-good">observed</span>
                ) : (
                  <span className="text-muted">not observed</span>
                ),
              }))}
            />
          </CompareMetric>

          <CompareMetric
            label="Destination latency"
            divergent={latencyDelta != null && latencyDelta > 1}
            icon={<IconNetwork className="h-3 w-3" />}
            note={
              latencyDelta != null
                ? `Δ ${formatRtt(latencyDelta)} ms between the fastest and slowest destination observation. Intermediate RTTs are not compared here.`
                : 'Fewer than two nodes observed the destination; no latency delta is computable.'
            }
          >
            <NodeMetricList
              rows={observedRows.map(({ node, rtt }) => ({
                name: node.node_name,
                value:
                  rtt != null ? (
                    <span className="tabular-nums">
                      {formatRtt(rtt)} ms
                    </span>
                  ) : (
                    <span className="text-dim">—</span>
                  ),
              }))}
            />
          </CompareMetric>

          <CompareMetric
            label="Probe response rate"
            divergent={
              new Set(
                replyRows.map(({ stats }) =>
                  stats.probes > 0 ? (stats.replies / stats.probes).toFixed(2) : 'n/a',
                ),
              ).size > 1
            }
            icon={<IconNetwork className="h-3 w-3" />}
            note="Successful ICMP probe replies, not end-to-end packet loss. Probe coverage depends on router filtering and query count."
          >
            <NodeMetricList
              rows={replyRows.map(({ node, stats }) => ({
                name: node.node_name,
                value:
                  stats.probes > 0
                    ? `${stats.replies}/${stats.probes} (${Math.round((stats.replies / stats.probes) * 100)}%)`
                    : '—',
              }))}
            />
          </CompareMetric>

          {nodeErrors.length > 0 ? (
            <CompareMetric
              label="Agent-reported errors"
              divergent
              icon={<IconAlert className="h-3 w-3" />}
              note="These are execution/transport errors reported by the selected agents. They describe the agent run, not a hop timeout along the network path."
            >
              <ul className="space-y-1">
                {nodeErrors.map((node) => (
                  <li key={node.node_id} className="text-[11px]">
                    <span className="text-muted">{node.node_name}: </span>
                    <span className="font-mono text-bad">
                      {node.error?.code}: {node.error?.message}
                    </span>
                  </li>
                ))}
              </ul>
            </CompareMetric>
          ) : null}
        </div>
      </section>
    </div>
  )
}
