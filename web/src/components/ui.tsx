import { useEffect, useId, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { ApiError } from '../api/client'
import { copyText } from '../lib/clipboard'
import { formatDurationMs } from '../lib/format'
import type { ToneMeta } from '../lib/status'
import { IconAlert, IconCheck, IconCopy, IconInfo, IconRefresh } from './Icons'

/* ------------------------------------------------------------------ */
/* Small building blocks                                               */
/* ------------------------------------------------------------------ */

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg
      className={`animate-spin ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  )
}

export function Skeleton({ className = 'h-4 w-full' }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden="true" />
}

export function StatusBadge({ meta, title }: { meta: ToneMeta; title?: string }) {
  return (
    <span className={`badge ${meta.badge}`} title={title}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} aria-hidden="true" />
      {meta.label}
    </span>
  )
}

export function InfoNote({
  tone = 'info',
  title,
  children,
}: {
  tone?: 'info' | 'warn'
  title?: string
  children: ReactNode
}) {
  const palette =
    tone === 'warn'
      ? 'border-warn/35 bg-warn/[0.055] text-warn'
      : 'border-accent/30 bg-accent/[0.045] text-accent'
  const Icon = tone === 'warn' ? IconAlert : IconInfo
  return (
    <div className={`rounded border px-2.5 py-2 text-[12px] ${palette}`}>
      <div className="flex items-start gap-2">
        <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        <div className="min-w-0 flex-1">
          {title ? <p className="font-mono text-[10px] uppercase tracking-wider">{title}</p> : null}
          <div className="text-fg-soft">{children}</div>
        </div>
      </div>
    </div>
  )
}

export function CopyButton({
  value,
  label,
  text,
  className = '',
  onResult,
}: {
  value: string
  label: string
  text?: string
  className?: string
  onResult?: (ok: boolean) => void
}) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    }
  }, [])

  const handleClick = async (): Promise<void> => {
    const ok = await copyText(value)
    onResult?.(ok)
    if (!ok) return
    setCopied(true)
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setCopied(false), 1400)
  }

  return (
    <button
      type="button"
      className={`inline-flex items-center gap-1 rounded px-1 py-0.5 text-[10px] text-dim transition-colors hover:bg-white/5 hover:text-fg focus-visible:text-fg ${copied ? 'text-good' : ''} ${className}`}
      onClick={() => {
        void handleClick()
      }}
      aria-label={copied ? `Copied ${label}` : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <IconCheck className="h-3 w-3" /> : <IconCopy className="h-3 w-3" />}
      {text ? <span>{copied ? 'copied' : text}</span> : null}
    </button>
  )
}

export function ErrorNote({
  error,
  onRetry,
  retryLabel = 'Retry',
  compact = false,
}: {
  error: ApiError
  onRetry?: () => void
  retryLabel?: string
  compact?: boolean
}) {
  const retrySeconds =
    error.status === 429 && error.retryAfterMs != null
      ? Math.max(1, Math.ceil(error.retryAfterMs / 1000))
      : null
  const gatewayFailure = error.status === 502 || error.status === 503 || error.status === 504

  return (
    <div
      role="alert"
      className={`rounded border border-bad/35 bg-bad/[0.06] ${compact ? 'px-2 py-1.5' : 'px-2.5 py-2'}`}
    >
      <div className="flex items-start gap-2">
        <IconAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-bad" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[12px] font-medium text-bad">Request failed</span>
            <span className="badge badge-square border-bad/30 bg-bad/10 text-bad/90">
              {error.code}
            </span>
            {error.status > 0 ? (
              <span className="font-mono text-[10px] text-dim">HTTP {error.status}</span>
            ) : null}
          </div>
          <p className="mt-0.5 break-words text-[12px] text-fg-soft">{error.message}</p>
          {retrySeconds !== null ? (
            <p className="mt-0.5 text-[11px] text-warn">
              Rate limited — retry after about {retrySeconds}s.
            </p>
          ) : null}
          {gatewayFailure ? (
            <p className="mt-0.5 text-[11px] text-warn">
              The Cloudflare tunnel or Controller is unreachable — check cloudflared
              and the Controller service, then retry.
            </p>
          ) : null}
        </div>
        {onRetry ? (
          <button type="button" className="btn btn-ghost btn-xs shrink-0" onClick={onRetry}>
            <IconRefresh className="h-3 w-3" />
            {retryLabel}
          </button>
        ) : null}
      </div>
    </div>
  )
}

export function EmptyState({
  title,
  children,
  action,
  icon,
}: {
  title: string
  children?: ReactNode
  action?: ReactNode
  icon?: ReactNode
}) {
  return (
    <div className="flex flex-col items-start gap-2 px-1 py-3">
      {icon ? <div className="text-dim">{icon}</div> : null}
      <p className="font-mono text-[12px] uppercase tracking-wider text-muted">{title}</p>
      {children ? <div className="max-w-prose text-[12px] text-dim">{children}</div> : null}
      {action}
    </div>
  )
}

export function SectionCard({
  step,
  title,
  subtitle,
  aside,
  children,
  id,
  className = '',
}: {
  step?: string
  title: string
  subtitle?: ReactNode
  aside?: ReactNode
  children: ReactNode
  id?: string
  className?: string
}) {
  const headingId = useId()
  return (
    <section id={id} aria-labelledby={headingId} className={`panel ${className}`}>
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-3 py-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {step ? (
              <span className="font-mono text-[10px] leading-none text-accent/80">{step}</span>
            ) : null}
            <h2
              id={headingId}
              className="font-mono text-[11px] font-semibold uppercase leading-none tracking-[0.16em] text-fg-soft"
            >
              {title}
            </h2>
          </div>
          {subtitle ? <p className="mt-1 text-[11px] leading-snug text-muted">{subtitle}</p> : null}
        </div>
        {aside ? <div className="shrink-0">{aside}</div> : null}
      </header>
      <div className="px-3 py-2.5">{children}</div>
    </section>
  )
}

export function MetaCell({
  label,
  children,
  title,
  mono = true,
}: {
  label: string
  children: ReactNode
  title?: string
  mono?: boolean
}) {
  return (
    <div className="min-w-0 px-2 py-1.5" title={title}>
      <dt className="micro">{label}</dt>
      <dd className={`mt-0.5 truncate text-[12px] text-fg-soft ${mono ? 'font-mono' : ''}`}>
        {children}
      </dd>
    </div>
  )
}

export function DurationLabel({ ms }: { ms: number | null | undefined }) {
  return <span className="num">{formatDurationMs(ms)}</span>
}
