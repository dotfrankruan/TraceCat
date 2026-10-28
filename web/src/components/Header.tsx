import type { Session } from '../api/types'
import { IconHistory, IconLock, IconLogo, IconLogout } from './Icons'
import { Spinner } from './ui'

const MODE_STYLES: Record<string, string> = {
  dev: 'border-warn/40 bg-warn/10 text-warn',
  local: 'border-accent/40 bg-accent/10 text-accent',
  cloudflare: 'border-magenta/40 bg-magenta/10 text-magenta',
}

function modeClass(mode: string): string {
  return MODE_STYLES[mode] ?? 'border-line-strong bg-ink-800 text-muted'
}

export function Header({
  session,
  onLogout,
  logoutBusy,
}: {
  session: Session
  onLogout: () => void
  logoutBusy: boolean
}) {
  const identity =
    session.user?.email ||
    session.user?.subject ||
    (session.mode === 'dev' ? 'loopback bypass' : 'authenticated')
  const identityTitle = [
    session.user?.email,
    session.user?.subject ? `subject: ${session.user.subject}` : '',
    session.user?.auth_method ? `auth: ${session.user.auth_method}` : '',
  ]
    .filter((part): part is string => typeof part === 'string' && part.length > 0)
    .join('\n')

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-ink-950/85 backdrop-blur supports-[backdrop-filter]:bg-ink-950/70">
      <div className="mx-auto flex h-14 max-w-[1680px] items-center gap-3 px-3 sm:px-4">
        <span className="text-accent">
          <IconLogo />
        </span>
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <span className="font-mono text-[15px] font-semibold tracking-[0.18em] text-fg">
              TraceCat
            </span>
            <span className="micro hidden sm:inline">network diagnostics</span>
          </div>
          <p className="hidden truncate text-[10px] leading-tight text-dim sm:block">
            distributed ICMP traceroute · controller-managed agents
          </p>
        </div>

        <div className="ml-auto flex min-w-0 items-center gap-2">
          <a href="#history" className="btn btn-ghost btn-xs xl:hidden">
            <IconHistory className="h-3.5 w-3.5" />
            History
          </a>
          <span
            className="badge hidden border-line-strong text-dim md:inline-flex"
            title={`Controller ${session.version}`}
          >
            v{session.version}
          </span>
          <span
            className={`badge ${modeClass(session.mode)}`}
            title={`Authentication mode: ${session.mode}`}
          >
            <IconLock className="h-2.5 w-2.5" />
            {session.mode}
          </span>
          <span
            className="hidden max-w-[220px] truncate font-mono text-[11px] text-muted lg:block"
            title={identityTitle || identity}
          >
            {identity}
          </span>
          {session.mode === 'local' ? (
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={onLogout}
              disabled={logoutBusy}
              aria-label={logoutBusy ? 'Signing out' : 'Sign out'}
            >
              {logoutBusy ? <Spinner className="h-3 w-3" /> : <IconLogout className="h-3 w-3" />}
              <span className="hidden sm:inline">{logoutBusy ? 'Signing out' : 'Sign out'}</span>
            </button>
          ) : null}
        </div>
      </div>
    </header>
  )
}
