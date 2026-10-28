import type { Protocol } from '../api/types'

/** Fixed probe-protocol enum shared with the controller and agents. */
export const ALL_PROTOCOLS: readonly Protocol[] = ['icmp', 'tcp', 'udp']

export const MIN_PORT = 1
export const MAX_PORT = 65535

/** NextTrace conventional defaults; the user may choose any bounded port. */
export const DEFAULT_PORTS: Readonly<Record<'tcp' | 'udp', number>> = {
  tcp: 80,
  udp: 33494,
}

const PROTOCOL_LABEL: Record<Protocol, string> = {
  icmp: 'ICMP',
  tcp: 'TCP',
  udp: 'UDP',
}

export function isProtocol(value: unknown): value is Protocol {
  return value === 'icmp' || value === 'tcp' || value === 'udp'
}

/**
 * Controller-enabled protocols, normalized and de-duplicated. Falls back to all
 * three when the session does not advertise an allowlist (pre-extended
 * controller), so the selector still works.
 */
export function normalizeProtocols(values: readonly string[] | undefined): Protocol[] {
  const protocols: Protocol[] = []
  for (const value of values ?? []) {
    const candidate = typeof value === 'string' ? value.trim().toLowerCase() : ''
    if (isProtocol(candidate) && !protocols.includes(candidate)) protocols.push(candidate)
  }
  return protocols.length > 0 ? protocols : [...ALL_PROTOCOLS]
}

/** TCP/UDP probe a destination port; ICMP does not. */
export function protocolRequiresPort(protocol: string | undefined): boolean {
  return protocol === 'tcp' || protocol === 'udp'
}

export function protocolLabel(protocol: Protocol | string | undefined): string {
  if (typeof protocol !== 'string') return '—'
  const normalized = protocol.trim().toLowerCase()
  if (normalized.length === 0) return '—'
  return isProtocol(normalized) ? PROTOCOL_LABEL[normalized] : normalized.toUpperCase()
}

/** Compact display for chips and dense metadata, e.g. `tcp/443`, `icmp`. */
export function probeLabel(
  protocol: Protocol | string | undefined,
  port?: number | null,
): string {
  const label = protocolLabel(protocol)
  if (!protocolRequiresPort(protocol)) return label
  return port != null ? `${label.toLowerCase()}/${port}` : label.toLowerCase()
}

export function defaultPortInput(protocol: Protocol): string {
  return protocol === 'tcp' || protocol === 'udp' ? String(DEFAULT_PORTS[protocol]) : ''
}

/**
 * Destination-port validation for TCP/UDP. Returns a human-readable error or
 * null when the value is a valid bounded integer. Ports are always integers in
 * 1..65535, never ranges or service names (docs/API.md §2.7).
 */
export function validatePortInput(value: string): string | null {
  const trimmed = value.trim()
  if (trimmed.length === 0) return 'Destination port is required for TCP/UDP.'
  if (!/^[0-9]+$/.test(trimmed)) return 'Port must be a whole number between 1 and 65535.'
  const numeric = Number(trimmed)
  if (!Number.isSafeInteger(numeric) || numeric < MIN_PORT || numeric > MAX_PORT) {
    return 'Port must be between 1 and 65535.'
  }
  return null
}

export function parsePortInput(value: string): number | null {
  if (validatePortInput(value) !== null) return null
  return Number(value.trim())
}
