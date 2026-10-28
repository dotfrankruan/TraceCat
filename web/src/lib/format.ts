/** Formatting helpers shared by the dashboard components. */

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
})

const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
})

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  if (min > max) return min
  return Math.min(Math.max(Math.trunc(value), min), max)
}

/** Round-trip time, e.g. `2.68` / `41.2`; em dash when unobserved. */
export function formatRtt(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return '—'
  if (ms <= 0) return '0.00'
  if (ms < 1) return ms.toFixed(3)
  if (ms < 10) return ms.toFixed(2)
  return ms.toFixed(1)
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  const seconds = ms / 1000
  if (seconds < 60) return `${seconds.toFixed(1)} s`
  const wholeSeconds = Math.round(seconds)
  const minutes = Math.floor(wholeSeconds / 60)
  const rest = wholeSeconds % 60
  return `${minutes}m ${String(rest).padStart(2, '0')}s`
}

export function formatSeconds(ms: number): string {
  return `${(ms / 1000).toFixed(ms % 1000 === 0 ? 0 : 1)} s`
}

export function formatClock(iso: string | undefined): string {
  if (!iso) return '—'
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return iso
  return timeFormatter.format(new Date(parsed))
}

/** Local wall-clock display; the raw RFC3339 timestamp is used for `title`. */
export function formatDateTime(iso: string | undefined): string {
  if (!iso) return '—'
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return iso
  return dateTimeFormatter.format(new Date(parsed))
}

/** Absolute UTC timestamp for tooltips; never fabricates a value. */
export function absoluteTimestamp(iso: string | undefined): string {
  if (!iso) return 'Not recorded'
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return iso
  return new Date(parsed).toISOString()
}

export function relativeTime(iso: string | undefined, now: number = Date.now()): string {
  if (!iso) return '—'
  const parsed = Date.parse(iso)
  if (Number.isNaN(parsed)) return '—'
  const deltaSeconds = (now - parsed) / 1000
  const future = deltaSeconds < -1
  const magnitude = Math.abs(deltaSeconds)
  const suffix = future ? 'from now' : 'ago'

  let value: string
  if (magnitude < 5) return future ? 'in a moment' : 'just now'
  else if (magnitude < 60) value = `${Math.floor(magnitude)}s`
  else if (magnitude < 3600) value = `${Math.floor(magnitude / 60)}m`
  else if (magnitude < 86_400) value = `${Math.floor(magnitude / 3600)}h`
  else if (magnitude < 2_592_000) value = `${Math.floor(magnitude / 86_400)}d`
  else value = `${Math.floor(magnitude / 2_592_000)}mo`

  return `${value} ${suffix}`
}

export function geoLabel(parts: Array<string | undefined>): string {
  return parts
    .map((part) => (part ?? '').trim())
    .filter((part) => part.length > 0)
    .join(' · ')
}

export function formatCoordinates(
  lat: number | null | undefined,
  lng: number | null | undefined,
): string {
  if (lat == null || lng == null || !Number.isFinite(lat) || !Number.isFinite(lng)) {
    return '—'
  }
  return `${lat.toFixed(4)}, ${lng.toFixed(4)}`
}

export function shortId(id: string | undefined, length = 8): string {
  if (!id) return '—'
  if (id.length <= length) return id
  return `${id.slice(0, length)}…`
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural
}

export function preferReducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

export function uniqueStrings(values: Array<string | undefined>): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const value of values) {
    const trimmed = (value ?? '').trim()
    if (trimmed.length === 0 || seen.has(trimmed)) continue
    seen.add(trimmed)
    result.push(trimmed)
  }
  return result
}

/** Trimmed, non-empty server messages (warnings, error details). */
export function nonEmptyStrings(values: string[] | undefined): string[] {
  return (values ?? [])
    .map((value) => (typeof value === 'string' ? value.trim() : ''))
    .filter((value) => value.length > 0)
}
