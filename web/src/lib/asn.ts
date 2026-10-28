/**
 * Deterministic ASN colour assignment.
 *
 * The same ASN / AS name always maps to the same hue bucket for the lifetime of
 * the page, so an AS is recognisable across tables, paths and comparisons. The
 * palette itself lives in index.css (`asn-tone-<n>`, `asn-chip`, `asn-edge`)
 * with text/background contrast checked for the dark theme.
 */

export const ASN_HUE_BUCKETS = 36

/** FNV-1a 32-bit; stable across sessions and browsers. */
export function hashAsnKey(key: string): number {
  let hash = 0x811c9dc5
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index)
    hash = Math.imul(hash, 0x01000193)
  }
  return hash >>> 0
}

export function asnHueBucket(key: string): number {
  return hashAsnKey(key) % ASN_HUE_BUCKETS
}

/** Colour class for a stable ASN identity key (e.g. `AS15169`). */
export function asnToneClass(key: string): string {
  return `asn-tone-${asnHueBucket(key)}`
}

/** Full chip class list, including the deterministic hue. */
export function asnChipClass(key: string): string {
  return `asn-chip ${asnToneClass(key)}`
}

/** Identity string used for hashing and labels; unknown stays neutral. */
export function asnIdentityKey(asn: number | undefined, asName: string | undefined): string {
  if (asn != null && Number.isFinite(asn)) return `AS${asn}`
  const name = (asName ?? '').trim()
  if (name.length > 0) return name.toLowerCase()
  return 'unknown'
}

/** Human ASN label; `null` when NextTrace reported no ASN at all. */
export function asnLabel(asn: number | undefined): string | null {
  if (asn == null || !Number.isFinite(asn)) return null
  return `AS${asn}`
}
