import { Fragment, useEffect, useMemo, useState } from 'react'
import type { NodeResult, Probe } from '../api/types'
import { asnChipClass, asnToneClass } from '../lib/asn'
import { buildPath, type HopView } from '../lib/hops'
import { formatCoordinates, formatRtt, preferReducedMotion } from '../lib/format'
import { IconChevronDown, IconChevronRight, IconNoReply } from './Icons'
import { CopyButton } from './ui'

const TH_CLASS =
  'whitespace-nowrap border-b border-line bg-ink-850/80 px-2 py-1.5 font-mono text-[9px] font-medium uppercase tracking-[0.12em] text-dim'

const TD_CLASS = 'px-2 py-1.5 align-top'

function ProbeField({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-dim">{label}</dt>
      <dd className="min-w-0 break-all text-fg-soft" title={value}>
        {value}
      </dd>
    </>
  )
}

function ProbeCard({ probe, index }: { probe: Probe; index: number }) {
  const geo =
    [probe.country, probe.region, probe.city]
      .map((part) => (part ?? '').trim())
      .filter((part) => part.length > 0)
      .join(' · ') || '—'

  return (
    <li className="min-w-0 rounded border border-line bg-ink-900/80 px-2 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="micro">probe {index + 1}</span>
        {probe.success ? (
          <span className="font-mono text-[9px] uppercase tracking-wider text-good">reply</span>
        ) : (
          <span className="font-mono text-[9px] uppercase tracking-wider text-muted">
            no reply{probe.error_code ? ` · ${probe.error_code}` : ''}
          </span>
        )}
      </div>
      {probe.success && probe.address ? (
        <div className="mt-0.5 flex items-start justify-between gap-1">
          <p className="min-w-0 break-all font-mono text-[11px] text-fg">{probe.address}</p>
          <span className="flex shrink-0 items-center gap-1">
            <span className="font-mono text-[10px] tabular-nums text-accent">
              {formatRtt(probe.rtt_ms)}
              {probe.rtt_ms != null ? ' ms' : ''}
            </span>
            <CopyButton value={probe.address} label={`Copy probe address ${probe.address}`} />
          </span>
        </div>
      ) : (
        <p className="mt-0.5 font-mono text-[11px] text-muted">
          no ICMP reply reported for this probe
        </p>
      )}
      <dl className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-[2px] text-[10px] leading-snug">
        <ProbeField label="ASN" value={probe.asn != null ? `AS${probe.asn}` : '—'} />
        <ProbeField label="AS org" value={probe.as_name?.trim() || '—'} />
        <ProbeField label="Owner" value={probe.owner?.trim() || '—'} />
        <ProbeField label="ISP" value={probe.isp?.trim() || '—'} />
        <ProbeField label="Prefix" value={probe.prefix?.trim() || '—'} />
        <ProbeField label="PTR" value={probe.ptr?.trim() || '—'} />
        <ProbeField label="Geo" value={geo} />
        <ProbeField label="Coords" value={formatCoordinates(probe.lat, probe.lng)} />
        <ProbeField
          label="MPLS"
          value={probe.mpls && probe.mpls.length > 0 ? probe.mpls.join(' · ') : '—'}
        />
      </dl>
    </li>
  )
}

function ReplyCell({ view }: { view: HopView }) {
  const firstAddress = view.addresses[0]

  if (view.noReply) {
    return (
      <div>
        <span
          className="inline-flex items-center gap-1 rounded border border-dashed border-line-strong bg-ink-850/70 px-1.5 py-0.5 text-[10px] text-muted"
          title="No ICMP reply for any probe at this TTL. Intermediate routers commonly drop probes; this does not prove the route is broken."
        >
          <IconNoReply className="h-3 w-3" />
          no reply
          {view.errorCodes.length > 0 ? (
            <span className="text-dim">({view.errorCodes.join(', ')})</span>
          ) : null}
        </span>
      </div>
    )
  }

  return (
    <div className="min-w-0">
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
        <span className="break-all font-mono text-[12px] text-fg" title={view.addresses.join(', ')}>
          {firstAddress ?? 'reply without address'}
        </span>
        <CopyButton value={firstAddress ?? ''} label={`Copy hop ${view.ttl} address`} />
        {view.addresses.length > 1 ? (
          <span className="font-mono text-[9px] text-dim" title={view.addresses.join('\n')}>
            +{view.addresses.length - 1} addr
          </span>
        ) : null}
      </div>
      {view.ptr ? (
        <p
          className="mt-0.5 max-w-[26rem] truncate font-mono text-[10px] leading-snug text-muted"
          title={view.ptr}
        >
          {view.ptr}
        </p>
      ) : null}
      {view.mpls.length > 0 ? (
        <span className="mt-1 flex flex-wrap items-center gap-1">
          <span className="font-mono text-[9px] uppercase tracking-wider text-dim">mpls</span>
          {view.mpls.slice(0, 3).map((label) => (
            <span
              key={label}
              className="rounded border border-line-strong bg-ink-850 px-1 py-px font-mono text-[9px] text-muted"
              title={view.mpls.join(' · ')}
            >
              {label}
            </span>
          ))}
          {view.mpls.length > 3 ? (
            <span
              className="font-mono text-[9px] text-dim"
              title={view.mpls.join(' · ')}
            >
              +{view.mpls.length - 3}
            </span>
          ) : null}
        </span>
      ) : null}
    </div>
  )
}

function NetworkCell({ view }: { view: HopView }) {
  if (view.noReply) {
    return <span className="font-mono text-[11px] text-dim">—</span>
  }
  return (
    <div className="min-w-0">
      <div className="flex items-center gap-1">
        {view.asn != null ? (
          <>
            <span
              className={`asn-chip ${asnToneClass(view.asnKey)}`}
              title={view.asName || 'Autonomous system'}
            >
              AS{view.asn}
            </span>
            <CopyButton value={`AS${view.asn}`} label={`Copy ASN for hop ${view.ttl}`} />
          </>
        ) : view.asName ? (
          <span className={`asn-chip ${asnChipClass(view.asnKey)}`} title={view.asName}>
            {view.asName}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-dim">no ASN</span>
        )}
      </div>
      <p
        className={`mt-0.5 max-w-[16rem] truncate text-[11px] ${view.asName ? 'text-fg-soft' : 'text-dim'}`}
        title={view.asName || 'Not reported by NextTrace'}
      >
        {view.asName || '—'}
      </p>
      <p
        className={`mt-0.5 max-w-[16rem] truncate text-[10px] ${view.geo ? 'text-muted' : 'text-dim'}`}
        title={view.geo || 'Not reported by NextTrace'}
      >
        {view.geo || 'geo not reported'}
      </p>
    </div>
  )
}

function HopRow({
  node,
  view,
  highlighted,
  expanded,
  onToggleExpanded,
}: {
  node: NodeResult
  view: HopView
  highlighted: boolean
  expanded: boolean
  onToggleExpanded: () => void
}) {
  const rowId = `hop-${node.node_id}-${view.ttl}`
  const detailId = `hop-probes-${node.node_id}-${view.ttl}`

  return (
    <Fragment>
      <tr
        id={rowId}
        tabIndex={-1}
        className={`border-t border-line/50 transition-colors ${
          highlighted ? 'hop-focus' : view.noReply ? 'hover:bg-white/[0.02]' : 'hover:bg-white/[0.025]'
        }`}
      >
        <td className={`${TD_CLASS} w-10`}>
          <span className="font-mono text-[11px] tabular-nums text-muted">{view.ttl}</span>
        </td>
        <td className={`${TD_CLASS} min-w-[15rem] max-w-[30rem]`}>
          <ReplyCell view={view} />
        </td>
        <td className={`${TD_CLASS} w-[8.5rem] whitespace-nowrap`}>
          {view.noReply || view.minRttMs == null ? (
            <span className="font-mono text-[11px] text-dim">—</span>
          ) : (
            <span
              className="font-mono text-[11px] tabular-nums text-fg-soft"
              title={`min ${view.minRttMs} ms · avg ${view.avgRttMs?.toFixed(2)} ms · max ${view.maxRttMs} ms`}
            >
              {formatRtt(view.minRttMs)}
              <span className="text-dim"> · </span>
              {formatRtt(view.avgRttMs)}
              <span className="text-dim"> · </span>
              {formatRtt(view.maxRttMs)}
            </span>
          )}
        </td>
        <td className={`${TD_CLASS} w-[14rem]`}>
          <NetworkCell view={view} />
        </td>
        <td className={`${TD_CLASS} w-9 text-right`}>
          <button
            type="button"
            className="inline-flex items-center justify-center rounded p-1 text-dim hover:bg-white/5 hover:text-fg"
            onClick={onToggleExpanded}
            aria-expanded={expanded}
            aria-controls={detailId}
            aria-label={`${expanded ? 'Hide' : 'Show'} probe samples for TTL ${view.ttl}`}
          >
            {expanded ? (
              <IconChevronDown className="h-3.5 w-3.5" />
            ) : (
              <IconChevronRight className="h-3.5 w-3.5" />
            )}
          </button>
        </td>
      </tr>
      {expanded ? (
        <tr id={detailId} className="border-t border-line/60 bg-ink-950/55">
          <td colSpan={5} className="px-3 py-2">
            <p className="micro mb-1.5">
              Probe samples · TTL {view.ttl} · {view.probes.length}{' '}
              {view.probes.length === 1 ? 'probe' : 'probes'}
            </p>
            <ol className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 2xl:grid-cols-3">
              {view.probes.map((probe, index) => (
                <ProbeCard key={index} probe={probe} index={index} />
              ))}
            </ol>
          </td>
        </tr>
      ) : null}
    </Fragment>
  )
}

export function HopTable({
  node,
  targetIP,
  highlightedTtl,
}: {
  node: NodeResult
  targetIP: string
  highlightedTtl: number | null
}) {
  const views = useMemo(() => buildPath(node.hops), [node.hops])
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(() => new Set())

  useEffect(() => {
    if (highlightedTtl == null) return
    const row = document.getElementById(`hop-${node.node_id}-${highlightedTtl}`)
    if (!row) return
    row.scrollIntoView({
      behavior: preferReducedMotion() ? 'auto' : 'smooth',
      block: 'center',
      inline: 'nearest',
    })
  }, [highlightedTtl, node.node_id, views.length])

  const toggleExpanded = (ttl: number): void => {
    setExpanded((previous) => {
      const next = new Set(previous)
      if (next.has(ttl)) next.delete(ttl)
      else next.add(ttl)
      return next
    })
  }

  return (
    <div className="mt-1">
      <div className="table-scroll">
        <table className="w-full min-w-[660px] border-collapse text-left">
          <caption className="sr-only">
            Hops from {node.node_name} to {targetIP}; each row shows the replies for one
            time-to-live value. “No reply” means the probe was not answered, not that the route is
            broken.
          </caption>
          <colgroup>
            <col className="w-10" />
            <col />
            <col className="w-[8.5rem]" />
            <col className="w-[14rem]" />
            <col className="w-9" />
          </colgroup>
          <thead>
            <tr>
              <th scope="col" className={`${TH_CLASS} w-10`}>
                TTL
              </th>
              <th scope="col" className={TH_CLASS}>
                Reply
                <span className="ml-1 normal-case tracking-normal text-dim">· ptr · mpls</span>
              </th>
              <th
                scope="col"
                className={TH_CLASS}
                title="Minimum, average and maximum RTT of successful probes"
              >
                RTT ms
                <span className="ml-1 normal-case tracking-normal text-dim">min·avg·max</span>
              </th>
              <th scope="col" className={TH_CLASS}>
                ASN
                <span className="ml-1 normal-case tracking-normal text-dim">· org · geo</span>
              </th>
              <th scope="col" className={`${TH_CLASS} text-right`}>
                <span className="sr-only">Probe details</span>
                <span aria-hidden="true">·</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {views.map((view) => (
              <HopRow
                key={view.ttl}
                node={node}
                view={view}
                highlighted={highlightedTtl === view.ttl}
                expanded={expanded.has(view.ttl)}
                onToggleExpanded={() => toggleExpanded(view.ttl)}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[9px] leading-snug text-dim">
        <span>— = not reported by NextTrace; values are never synthesized.</span>
        <span>
          no reply = unanswered ICMP probe. Intermediate routers routinely drop probes; it is not
          proof of a broken route.
        </span>
      </p>
    </div>
  )
}
