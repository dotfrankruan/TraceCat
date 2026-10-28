import type { ApiError } from './api/client'
import type { ResolveResponse } from './api/types'

/** App-level UI state shared across components (never sent to the server). */
export type ResolveState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: ResolveResponse }
  | { status: 'error'; error: ApiError }

export type ViewMode = 'detailed' | 'compare'

export type ToastKind = 'error' | 'success' | 'info' | 'warn'

export interface ToastItem {
  id: number
  kind: ToastKind
  text: string
}
