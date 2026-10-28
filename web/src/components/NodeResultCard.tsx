import type { NodeResult } from '../api/types'
import {
  destinationObserved,
  destinationRttMs,
  observedHopCount,
  replyStats,
  buildPath,
  type HopView,
} from '../lib/hops'
import { formatDurationMs, formatRtt, absoluteTimestamp } from '../lib/format'
import { probeLabel } from '../lib/protocols'
import { nodeStatusMeta } from '../lib/status'
import { AsPath } from './AsPath'
import { HopTable } from './HopTable'
import { CopyButton, InfoNote, Skeleton, StatusBadge } from './ui'

function SummaryCell({
  label,
  title,
  children,
}: {
  label: string
  title?: string
  children: React.ReactNode
}) {
  return (
    <div className="min-w-0 px-2.5 py-1.5" title={title}>
      <p className="micro">{label}</p>
      <div className="mt-0.5 truncate text-[12px] text-fg-soft">{children}</div>
    </div>
  )
}

function WaitingState({ status }: { status: string }) {
  const label =
    status === 'running'
      ? 'Trace in progress — waiting for the agent to report hops.'
      : 'Queued — waiting for the agent to accept this trace.'
  return (
    <div role="status" className="py-1">
      <p className="flex items-center gap-2 font-mono text-[11px] text-muted">
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            status === 'running' ? 'bg-accent motion-safe:animate-pulse' : 'bg-dim'
          }`}
          aria-hidden="true"
        />
        {label}
      </p>
      <div className="mt-2 space-y-1" aria-hidden="true">
        <Skeleton className="h-5 w-full" />
        <Skeleton className="h-5 w-full" />
        <Skeleton className="h-5 w-3/4" />
      </div>
    </div>
  )
}

function TerminalWithoutHops({ node }: { node: NodeResult }) {
  const copy: Record<string, string> = {
    timed_out:
      'The agent did not finish within the execution timeout. No hop path was reported; this says nothing conclusive about the route itself.',
    failed:
      'The agent reported an execution error. This is not a hop timeout and does not by itself describe the network path.',
    cancelled:
      'The job was cancelled before this agent reported a hop path. No conclusion can be drawn from the missing data.',
  }
  return (
    <InfoNote tone="warn" title="No hop data reported">
      <p>{copy[node.status] ?? 'The agent did not report any hop data for this trace.'}</p>
    </InfoNote>
  )
}

export function NodeResultCard({
  node,
  targetIP,
  protocol,
  port,
  highlightedTtl,
  onJump,
}: {
  node: NodeResult
  targetIP: string
  protocol: string
  port?: number | null
  highlightedTtl: number | null
  onJump: (nodeId: string, ttl: number) => void
}) {
  const meta = nodeStatusMeta(node.status)
  const summary = node.summary
  const replies = replyStats(node)
  const observed = destinationObserved(node)
  const destRtt = destinationRttMs(node)
  const hopCount = observedHopCount(node)
  const views: HopView[] = buildPath(node.hops)
  const hasHops = views.length > 0
  const inProgress = node.status === 'pending' || node.status === 'running'
  const replyPercent =
    replies.replyRate == null ? null : Math.round(replies.replyRate * 100)
  const nodeSubtitle = [node.location, node.provider].filter((part) => part && part.length > 0)

  return (
    <article
      id={`node-${node.node_id}`}
      className={`panel overflow-hidden border ${meta.surface}`}
      aria-labelledby={`node-heading-${node.node_id}`}
    >
      <header className="flex flex-wrap items-start justify-between gap-2 border-b border-line/70 px-3 py-2">
        <div className="flex min-w-0 items-start gap-2">
          <span
            className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${meta.dot}`}
            aria-hidden="true"
          />
          <div className="min-w-0">
            <h3
              id={`node-heading-${node.node_id}`}
              className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[13px] font-semibold text-fg"
            >
              {node.node_name}
              <span className="font-mono text-[10px] font-normal text-dim">{node.node_id}</span>
            </h3>
            <p className="mt-0.5 truncate text-[10px] text-muted" title={nodeSubtitle.join(' · ')}>
              {nodeSubtitle.length > 0 ? nodeSubtitle.join(' · ') : 'location not configured'}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span
            className="badge badge-square border-line-strong text-muted"
            title={
              node.interface
                ? `Reported source interface: ${node.interface}`
                : 'Automatic routing — the OS chooses the egress interface'
            }
          >
            {node.interface ? `iface ${node.interface}` : 'iface auto'}
          </span>
          <span
            className="badge badge-square border-line-strong text-muted"
            title="Probe protocol and destination port"
          >
            {probeLabel(protocol, port)}
          </span>
          <StatusBadge meta={meta} />
          <span
            className="font-mono text-[10px] text-dim"
            title={
              node.started_at
                ? `Started ${absoluteTimestamp(node.started_at)}`
                : 'Not started yet'
            }
          >
            {formatDurationMs(node.duration_ms)}
          </span>
        </div>
      </header>

      <div className="grid grid-cols-2 gap-px border-b border-line/60 bg-line/40 sm:grid-cols-3 lg:grid-cols-6">
        <SummaryCell label="Hops" title="Observed TTL groups">
          <span className="num">{hasHops || summary ? hopCount : '—'}</span>
        </SummaryCell>
        <SummaryCell
          label="Destination"
          title="Only an observed reply from the exact target IP counts as reached. Missing intermediate replies are not failures."
        >
          {observed ? (
            <span className="text-good">observed</span>
          ) : inProgress ? (
            <span className="text-dim">pending</span>
          ) : (
            <span className="text-muted">not observed</span>
          )}
        </SummaryCell>
        <SummaryCell label="Dest. latency" title="Minimum RTT observed to the exact destination">
          {destRtt != null ? (
            <span className="num text-fg">
              {formatRtt(destRtt)} <span className="text-dim">ms</span>
            </span>
          ) : (
            <span className="text-dim">—</span>
          )}
        </SummaryCell>
        <SummaryCell
          label="Probe replies"
          title="Successful ICMP probe replies across all hops. This is not end-to-end packet loss."
        >
          {replies.probes > 0 ? (
            <span className="num">
              {replies.replies}/{replies.probes}
              {replyPercent != null ? <span className="text-dim"> · {replyPercent}%</span> : null}
            </span>
          ) : (
            <span className="text-dim">—</span>
          )}
        </SummaryCell>
        <SummaryCell label="NextTrace" title="Version reported by the agent">
          <span className="font-mono text-[11px]">{node.nexttrace_version || '—'}</span>
        </SummaryCell>
        <SummaryCell label="Duration" title="Agent execution wall time">
          <span className="num">{formatDurationMs(node.duration_ms)}</span>
        </SummaryCell>
      </div>

      <div className="px-3 py-2.5">
        {node.error ? (
          <div className="mb-2">
            <InfoNote tone="warn" title="Agent-reported error">
              <p className="font-mono text-[11px]">
                {node.error.code}: {node.error.message}
              </p>
              <p className="mt-1 text-[11px] text-muted">
                This is an execution or transport error from the agent, not evidence about an
                intermediate router along the path.
              </p>
            </InfoNote>
          </div>
        ) : null}

        {hasHops ? (
          <>
            <AsPath
              nodeId={node.node_id}
              nodeName={node.node_name}
              views={views}
              highlightedTtl={highlightedTtl}
              onJump={onJump}
            />
            <HopTable node={node} targetIP={targetIP} highlightedTtl={highlightedTtl} />
          </>
        ) : inProgress ? (
          <WaitingState status={node.status} />
        ) : node.error ? null : (
          <TerminalWithoutHops node={node} />
        )}
      </div>

      <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-line/60 px-3 py-1.5">
        <p className="text-[10px] text-dim">
          {node.parser_schema ? (
            <span className="font-mono">parser {node.parser_schema}</span>
          ) : (
            'no parser output'
          )}
        </p>
        <CopyButton
          value={JSON.stringify(node, null, 2)}
          label={`Copy full result JSON for ${node.node_name}`}
          text="copy result"
        />
      </footer>
    </article>
  )
}
