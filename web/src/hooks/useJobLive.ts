import { useEffect, useRef, useState } from 'react'
import { ApiError, getJob, jobEventsUrl } from '../api/client'
import type { Job } from '../api/types'
import { isTerminalJob } from '../lib/status'

/**
 * Live job updates.
 *
 * Primary transport is the controller's SSE endpoint, which emits complete Job
 * snapshots on state changes only. It is NOT hop-by-hop probe streaming and the
 * UI must not present it as such. If SSE cannot be established or errors, we
 * fall back to polling `GET /api/v1/jobs/{id}` every 3 seconds until the job
 * reaches a terminal state or the component unmounts.
 */
export type JobLiveMode = 'idle' | 'connecting' | 'sse' | 'polling'

export interface JobLiveCallbacks {
  onJob: (job: Job) => void
  onSessionExpired: () => void
  onTransportError?: (message: string) => void
}

const POLL_INTERVAL_MS = 3000
const SSE_OPEN_TIMEOUT_MS = 8000

function isJobShape(value: unknown): value is Job {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<Job>
  return (
    typeof candidate.id === 'string' &&
    typeof candidate.status === 'string' &&
    typeof candidate.target_ip === 'string' &&
    Array.isArray(candidate.nodes)
  )
}

/** Tolerate both `data: <Job>` and `data: {"job": <Job>}` payloads. */
function parseSnapshot(data: string): Job | null {
  try {
    const parsed: unknown = JSON.parse(data)
    if (isJobShape(parsed)) return parsed
    if (parsed && typeof parsed === 'object' && 'job' in parsed) {
      const wrapped = (parsed as { job: unknown }).job
      if (isJobShape(wrapped)) return wrapped
    }
    return null
  } catch {
    return null
  }
}

export function useJobLive(job: Job | null, callbacks: JobLiveCallbacks): JobLiveMode {
  const [mode, setMode] = useState<JobLiveMode>('idle')
  const callbacksRef = useRef(callbacks)
  callbacksRef.current = callbacks

  const jobId = job?.id ?? null
  const terminal = job != null && isTerminalJob(job.status)

  useEffect(() => {
    if (!jobId || terminal) {
      setMode('idle')
      return
    }

    let disposed = false
    let source: EventSource | null = null
    let pollTimer: number | null = null
    let openTimer: number | null = null
    let pollInFlight = false
    let reportedTransportError = false
    let opened = false

    const clearTimers = (): void => {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer)
        pollTimer = null
      }
      if (openTimer !== null) {
        window.clearTimeout(openTimer)
        openTimer = null
      }
    }

    const reportTransportError = (): void => {
      if (reportedTransportError) return
      reportedTransportError = true
      callbacksRef.current.onTransportError?.(
        'Live updates interrupted — falling back to polling every 3 seconds.',
      )
    }

    const fetchSnapshot = async (): Promise<void> => {
      if (disposed || pollInFlight) return
      pollInFlight = true
      try {
        const response = await getJob(jobId)
        if (disposed) return
        callbacksRef.current.onJob(response.job)
      } catch (error) {
        if (disposed) return
        if (error instanceof ApiError && error.isUnauthorized) {
          disposed = true
          source?.close()
          source = null
          clearTimers()
          callbacksRef.current.onSessionExpired()
          return
        }
        reportTransportError()
      } finally {
        pollInFlight = false
      }
    }

    const startPolling = (): void => {
      if (disposed || pollTimer !== null) return
      if (source) {
        source.close()
        source = null
      }
      if (openTimer !== null) {
        window.clearTimeout(openTimer)
        openTimer = null
      }
      setMode('polling')
      void fetchSnapshot()
      pollTimer = window.setInterval(() => {
        void fetchSnapshot()
      }, POLL_INTERVAL_MS)
    }

    setMode('connecting')
    try {
      source = new EventSource(jobEventsUrl(jobId))
      source.onopen = () => {
        if (disposed) return
        opened = true
        if (openTimer !== null) {
          window.clearTimeout(openTimer)
          openTimer = null
        }
        setMode('sse')
      }
      source.addEventListener('job', (event) => {
        if (disposed) return
        const snapshot = parseSnapshot((event as MessageEvent<string>).data)
        if (snapshot) callbacksRef.current.onJob(snapshot)
      })
      source.onerror = () => {
        if (disposed) return
        reportTransportError()
        startPolling()
      }
      openTimer = window.setTimeout(() => {
        if (!disposed && !opened) startPolling()
      }, SSE_OPEN_TIMEOUT_MS)
    } catch {
      reportTransportError()
      startPolling()
    }

    return () => {
      disposed = true
      source?.close()
      clearTimers()
    }
  }, [jobId, terminal])

  return mode
}
