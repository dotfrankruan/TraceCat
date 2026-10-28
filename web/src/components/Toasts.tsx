import type { ToastItem, ToastKind } from '../types'
import { IconAlert, IconCheck, IconClose, IconInfo } from './Icons'

const KIND_STYLES: Record<ToastKind, string> = {
  error: 'border-bad/45 bg-ink-850 text-fg',
  success: 'border-good/45 bg-ink-850 text-fg',
  info: 'border-accent/40 bg-ink-850 text-fg',
  warn: 'border-warn/45 bg-ink-850 text-fg',
}

const KIND_ICON: Record<ToastKind, string> = {
  error: 'text-bad',
  success: 'text-good',
  info: 'text-accent',
  warn: 'text-warn',
}

const KIND_LABEL: Record<ToastKind, string> = {
  error: 'Error',
  success: 'Success',
  info: 'Info',
  warn: 'Warning',
}

export function Toasts({
  items,
  onDismiss,
}: {
  items: ToastItem[]
  onDismiss: (id: number) => void
}) {
  return (
    <div
      className="pointer-events-none fixed inset-x-3 bottom-3 z-50 flex flex-col items-end gap-2 sm:left-auto sm:right-4 sm:bottom-4 sm:max-w-sm"
      aria-live="polite"
      aria-atomic="false"
    >
      {items.map((item) => (
        <div
          key={item.id}
          role="status"
          className={`toast-in pointer-events-auto flex w-full items-start gap-2 rounded-md border px-3 py-2 shadow-lg shadow-black/40 ${KIND_STYLES[item.kind]}`}
        >
          <span className={`mt-0.5 shrink-0 ${KIND_ICON[item.kind]}`}>
            {item.kind === 'success' ? (
              <IconCheck className="h-4 w-4" />
            ) : item.kind === 'error' ? (
              <IconAlert className="h-4 w-4" />
            ) : (
              <IconInfo className="h-4 w-4" />
            )}
          </span>
          <div className="min-w-0 flex-1">
            <p className="micro">{KIND_LABEL[item.kind]}</p>
            <p className="mt-0.5 break-words text-[12px] text-fg-soft">{item.text}</p>
          </div>
          <button
            type="button"
            className="shrink-0 rounded p-0.5 text-dim hover:bg-white/5 hover:text-fg"
            onClick={() => onDismiss(item.id)}
            aria-label="Dismiss notification"
          >
            <IconClose className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}
