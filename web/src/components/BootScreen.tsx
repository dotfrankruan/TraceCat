import { IconAlert, IconLogo, IconRefresh } from './Icons'
import { Spinner } from './ui'

export function BootScreen() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 px-6">
      <div className="flex items-center gap-3 text-accent">
        <IconLogo />
        <span className="font-mono text-lg font-semibold tracking-[0.22em] text-fg">TraceCat</span>
      </div>
      <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-widest text-muted">
        <Spinner className="h-3.5 w-3.5 text-accent" />
        Establishing session…
      </div>
      <div className="skeleton h-2 w-48" aria-hidden="true" />
    </div>
  )
}

export function BootErrorScreen({
  message,
  onRetry,
  busy,
}: {
  message: string
  onRetry: () => void
  busy: boolean
}) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="panel w-full max-w-md">
        <div className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="text-accent">
            <IconLogo />
          </span>
          <span className="font-mono text-sm font-semibold tracking-[0.2em]">TraceCat</span>
        </div>
        <div className="px-4 py-4">
          <div className="flex items-start gap-2 rounded border border-bad/35 bg-bad/[0.06] px-3 py-2">
            <IconAlert className="mt-0.5 h-4 w-4 shrink-0 text-bad" />
            <div>
              <p className="font-mono text-[11px] uppercase tracking-wider text-bad">
                Session unavailable
              </p>
              <p className="mt-1 break-words text-[12px] text-fg-soft">{message}</p>
            </div>
          </div>
          <p className="mt-3 text-[12px] text-muted">
            The dashboard could not verify its session with the controller. This is usually
            temporary; retry before reloading the page.
          </p>
          <button
            type="button"
            className="btn btn-primary mt-4 w-full"
            onClick={onRetry}
            disabled={busy}
          >
            {busy ? <Spinner className="h-3.5 w-3.5" /> : <IconRefresh className="h-3.5 w-3.5" />}
            {busy ? 'Checking…' : 'Retry session check'}
          </button>
        </div>
      </div>
    </div>
  )
}
