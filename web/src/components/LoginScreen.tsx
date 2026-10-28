import { useState } from 'react'
import type { FormEvent } from 'react'
import type { ApiError } from '../api/client'
import { IconAlert, IconLock, IconLogo, IconRefresh } from './Icons'
import { Spinner } from './ui'

export function loginErrorMessage(error: ApiError | null): string | null {
  if (!error) return null
  switch (error.code) {
    case 'unauthorized':
      return 'Incorrect password.'
    case 'rate_limited': {
      const seconds =
        error.retryAfterMs != null ? Math.max(1, Math.ceil(error.retryAfterMs / 1000)) : null
      return seconds
        ? `Too many attempts. Try again in about ${seconds}s.`
        : 'Too many attempts. Try again shortly.'
    }
    case 'not_found':
      return 'Password login is disabled on this controller. If it uses Cloudflare Access, complete sign-in upstream and retry the session check.'
    case 'csrf_failed':
      return 'The security check failed. Reload the page and try again.'
    default:
      return error.message
  }
}

export function LoginScreen({
  expiredNotice,
  error,
  busy,
  onLogin,
  onRetrySession,
}: {
  expiredNotice: string | null
  error: ApiError | null
  busy: boolean
  onLogin: (password: string) => void
  onRetrySession: () => void
}) {
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const message = loginErrorMessage(error)

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    if (busy || password.length === 0) return
    onLogin(password)
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-10">
      <div className="mb-6 flex flex-col items-center gap-3 text-center">
        <span className="text-accent">
          <IconLogo />
        </span>
        <div>
          <h1 className="font-mono text-xl font-semibold tracking-[0.24em] text-fg">TraceCat</h1>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.18em] text-dim">
            distributed ICMP traceroute · network diagnostics
          </p>
        </div>
      </div>

      <div className="panel w-full max-w-sm">
        <div className="border-b border-line px-4 py-3">
          <h2 className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] text-fg-soft">
            <IconLock className="h-3.5 w-3.5 text-accent" />
            Controller sign-in
          </h2>
          <p className="mt-1 text-[11px] text-muted">
            This deployment uses local password authentication. Sessions are stored in an
            HttpOnly cookie.
          </p>
        </div>

        <form className="px-4 py-4" onSubmit={handleSubmit} aria-describedby="login-help">
          {expiredNotice ? (
            <div className="mb-3 rounded border border-warn/35 bg-warn/[0.055] px-2.5 py-2 text-[12px] text-warn">
              {expiredNotice}
            </div>
          ) : null}

          {message ? (
            <div
              role="alert"
              className="mb-3 flex items-start gap-2 rounded border border-bad/35 bg-bad/[0.06] px-2.5 py-2"
            >
              <IconAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-bad" />
              <p className="break-words text-[12px] text-fg-soft">{message}</p>
            </div>
          ) : null}

          <label
            htmlFor="login-password"
            className="micro mb-1 block text-fg-soft"
          >
            Administrator password
          </label>
          <div className="relative">
            <input
              id="login-password"
              type={showPassword ? 'text' : 'password'}
              className="input pr-14"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              autoFocus
              required
              aria-invalid={error != null}
              disabled={busy}
            />
            <button
              type="button"
              className="absolute inset-y-0 right-1 my-auto h-6 rounded px-2 font-mono text-[10px] uppercase tracking-wider text-dim hover:bg-white/5 hover:text-fg"
              onClick={() => setShowPassword((value) => !value)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? 'hide' : 'show'}
            </button>
          </div>

          <button
            type="submit"
            className="btn btn-primary mt-3 w-full"
            disabled={busy || password.length === 0}
          >
            {busy ? <Spinner className="h-3.5 w-3.5" /> : null}
            {busy ? 'Verifying…' : 'Unlock dashboard'}
          </button>

          <p id="login-help" className="mt-3 text-[11px] leading-relaxed text-dim">
            Cloudflare Access and loopback dev deployments authenticate before this screen. If
            this controller uses one of them, finish sign-in upstream and retry the session check.
          </p>

          <button
            type="button"
            className="btn btn-ghost btn-xs mt-2"
            onClick={onRetrySession}
            disabled={busy}
          >
            <IconRefresh className="h-3 w-3" />
            Retry session check
          </button>
        </form>
      </div>

      <p className="mt-6 max-w-sm text-center font-mono text-[10px] leading-relaxed text-dim">
        Passwords are never sent to agents. TraceCat only resolves targets on the controller and
        stores the display metadata you enter for this trace.
      </p>
    </div>
  )
}
