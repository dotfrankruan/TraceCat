import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { IconAlert } from './Icons'

interface ErrorBoundaryProps {
  children: ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

/**
 * Last-resort UI guard. A render failure must never leave the dashboard blank;
 * the fallback intentionally contains no data or configuration.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('TraceCat dashboard render error', error, info.componentStack)
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center px-4">
          <div className="panel max-w-md px-5 py-5" role="alert">
            <div className="flex items-center gap-2 text-bad">
              <IconAlert className="h-5 w-5" />
              <h1 className="font-mono text-sm font-semibold uppercase tracking-widest">
                Dashboard error
              </h1>
            </div>
            <p className="mt-2 text-[13px] text-fg-soft">
              The TraceCat dashboard hit an unexpected rendering error. Reloading usually
              recovers it; no job data was modified.
            </p>
            <button
              type="button"
              className="btn btn-primary mt-4"
              onClick={() => window.location.reload()}
            >
              Reload dashboard
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
