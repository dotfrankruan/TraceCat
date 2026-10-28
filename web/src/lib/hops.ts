import type { Hop, NodeResult, Probe, TraceSummary } from '../api/types'
import { asnIdentityKey } from './asn'
import { uniqueStrings } from './format'

/** Derived, presentation-only view of one TTL group. Never invents metadata. */
export interface HopView {
  ttl: number
  probes: Probe[]
  replies: Probe[]
  noReply: boolean
  /** First successful probe, preferring one with ASN/geo metadata. */
  primary: Probe | null
  addresses: string[]
  minRttMs?: number
  avgRttMs?: number
  maxRttMs?: number
  asn?: number
  asName: string
  asnKey: string
  country: string
  region: string
  city: string
  geo: string
  ptr: string
  owner: string
  isp: string
  prefix: string
  mpls: string[]
  lat?: number
  lng?: number
  errorCodes: string[]
}

function numericRtts(probes: Probe[]): number[] {
  const values: number[] = []
  for (const probe of probes) {
    if (probe.rtt_ms != null && Number.isFinite(probe.rtt_ms)) values.push(probe.rtt_ms)
  }
  return values
}

export function buildHopView(hop: Hop): HopView {
  const probes = Array.isArray(hop.probes) ? hop.probes : []
  const replies = probes.filter((probe) => probe.success)
  const rtts = numericRtts(replies)

  const primary =
    replies.find((probe) => probe.asn != null) ??
    replies.find((probe) => (probe.as_name ?? '').length > 0) ??
    replies[0] ??
    probes[0] ??
    null

  const geoProbe =
    replies.find((probe) => (probe.country ?? '').length > 0) ??
    replies.find((probe) => (probe.region ?? '').length > 0) ??
    primary
  const ptrProbe = replies.find((probe) => (probe.ptr ?? '').length > 0) ?? primary
  const ownerProbe =
    replies.find((probe) => (probe.owner ?? '').length > 0) ??
    replies.find((probe) => (probe.isp ?? '').length > 0) ??
    primary

  const asn = primary?.asn
  const asName = (primary?.as_name ?? '').trim()
  const country = (geoProbe?.country ?? '').trim()
  const region = (geoProbe?.region ?? '').trim()
  const city = (geoProbe?.city ?? '').trim()

  return {
    ttl: hop.ttl,
    probes,
    replies,
    noReply: replies.length === 0,
    primary,
    addresses: uniqueStrings(replies.map((probe) => probe.address)),
    minRttMs: rtts.length > 0 ? Math.min(...rtts) : undefined,
    avgRttMs: rtts.length > 0 ? rtts.reduce((sum, value) => sum + value, 0) / rtts.length : undefined,
    maxRttMs: rtts.length > 0 ? Math.max(...rtts) : undefined,
    asn,
    asName,
    asnKey: asnIdentityKey(asn, asName),
    country,
    region,
    city,
    geo: [country, region, city].filter((part) => part.length > 0).join(' · '),
    ptr: (ptrProbe?.ptr ?? '').trim(),
    owner: (ownerProbe?.owner ?? '').trim(),
    isp: (ownerProbe?.isp ?? '').trim(),
    prefix: (ownerProbe?.prefix ?? '').trim(),
    mpls: uniqueStrings(probes.flatMap((probe) => probe.mpls ?? [])),
    lat: geoProbe?.lat,
    lng: geoProbe?.lng,
    errorCodes: uniqueStrings(probes.filter((probe) => !probe.success).map((probe) => probe.error_code)),
  }
}

/** Sorted hop views for a node; empty when the node has no hop data yet. */
export function buildPath(hops: Hop[] | undefined): HopView[] {
  return [...(hops ?? [])].sort((left, right) => left.ttl - right.ttl).map(buildHopView)
}

/**
 * Identity used to compare AS paths. Answered hops contribute their ASN (or AS
 * name / address fallback); no-reply hops are skipped because routers commonly
 * drop probe replies and a gap is not a path change.
 */
export function answerKey(hop: HopView): string | null {
  if (hop.noReply) return null
  if (hop.asn != null) return `AS${hop.asn}`
  if (hop.asName.length > 0) return hop.asName
  return hop.primary?.address ?? null
}

/** Collapsed consecutive AS sequence and the number of transitions. */
export function asnPath(views: HopView[]): { sequence: string[]; transitions: number } {
  const sequence: string[] = []
  for (const view of views) {
    const key = answerKey(view)
    if (!key) continue
    if (sequence.length === 0 || sequence[sequence.length - 1] !== key) {
      sequence.push(key)
    }
  }
  return { sequence, transitions: Math.max(0, sequence.length - 1) }
}

export function asnPathForNode(node: NodeResult): { sequence: string[]; transitions: number } {
  return asnPath(buildPath(node.hops))
}

export interface ReplyStats {
  replies: number
  probes: number
  replyRate: number | null
}

/** Reply counts derived from the node summary, or from hops when absent. */
export function replyStats(node: NodeResult): ReplyStats {
  const summary: TraceSummary | undefined = node.summary
  if (summary) {
    return {
      replies: summary.replies,
      probes: summary.probes,
      replyRate: summary.probes > 0 ? summary.replies / summary.probes : null,
    }
  }
  let replies = 0
  let probes = 0
  for (const hop of node.hops ?? []) {
    for (const probe of hop.probes ?? []) {
      probes += 1
      if (probe.success) replies += 1
    }
  }
  return { replies, probes, replyRate: probes > 0 ? replies / probes : null }
}

export function destinationObserved(node: NodeResult): boolean {
  return node.summary?.reached_destination === true
}

export function destinationRttMs(node: NodeResult): number | undefined {
  const value = node.summary?.destination_rtt_ms
  return value != null && Number.isFinite(value) ? value : undefined
}

export function observedHopCount(node: NodeResult): number {
  return node.summary?.hop_count ?? node.hops?.length ?? 0
}

/** Highest observed TTL across a set of nodes (0 when nothing has arrived). */
export function maxObservedTtl(nodes: NodeResult[]): number {
  let max = 0
  for (const node of nodes) {
    for (const hop of node.hops ?? []) {
      if (hop.ttl > max) max = hop.ttl
    }
  }
  return max
}

export function findHopByTtl(hops: Hop[] | undefined, ttl: number): HopView | null {
  const hop = (hops ?? []).find((candidate) => candidate.ttl === ttl)
  return hop ? buildHopView(hop) : null
}
