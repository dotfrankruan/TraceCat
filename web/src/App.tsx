import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ApiError,
  cancelJob,
  createJob,
  downloadJobExport,
  fetchSession,
  getJob,
  listJobs,
  listNodes,
  login,
  logout,
  resolveTarget,
  setCsrfToken,
  toApiError,
} from './api/client'
import type {
  CreateJobRequest,
  Job,
  JobListItem,
  NodeInfo,
  Protocol,
  Session,
} from './api/types'
import { AgentPanel } from './components/AgentPanel'
import { BootErrorScreen, BootScreen } from './components/BootScreen'
import { Header } from './components/Header'
import { HistoryPanel } from './components/HistoryPanel'
import { IconNetwork } from './components/Icons'
import { JobPanel, JobPanelSkeleton } from './components/JobPanel'
import { LoginScreen } from './components/LoginScreen'
import { RunPanel } from './components/RunPanel'
import { TargetPanel } from './components/TargetPanel'
import { Toasts } from './components/Toasts'
import { CopyButton, InfoNote } from './components/ui'
import { useJobLive } from './hooks/useJobLive'
import { copyText } from './lib/clipboard'
import {
  clamp,
  formatSeconds,
  preferReducedMotion,
  shortId,
} from './lib/format'
import {
  DEFAULT_PORTS,
  normalizeProtocols,
  parsePortInput,
  probeLabel,
  protocolRequiresPort,
  validatePortInput,
} from './lib/protocols'
import { isTerminalJob, jobStatusMeta } from './lib/status'
import type { ResolveState, ToastItem, ToastKind, ViewMode } from './types'

type BootState =
  | { status: 'loading' }
  | { status: 'anon'; reason: 'unauthenticated' | 'expired'; notice?: string }
  | { status: 'error'; message: string }
  | { status: 'ready'; session: Session }

const DEFAULT_MAX_HOPS = 30
const DEFAULT_QUERIES = 3
const DEFAULT_TIMEOUT_MS = 60_000
const HISTORY_PAGE_LIMIT = 20
const HIGHLIGHT_MS = 3200

export function App() {
  const [boot, setBoot] = useState<BootState>({ status: 'loading' })
  const [loginBusy, setLoginBusy] = useState(false)
  const [loginError, setLoginError] = useState<ApiError | null>(null)
  const [logoutBusy, setLogoutBusy] = useState(false)

  const [nodes, setNodes] = useState<NodeInfo[]>([])
  const [nodesBusy, setNodesBusy] = useState(false)
  const [nodesError, setNodesError] = useState<ApiError | null>(null)
  const [selectedNodeIds, setSelectedNodeIds] = useState<string[]>([])

  const [targetInput, setTargetInput] = useState('')
  const [resolveState, setResolveState] = useState<ResolveState>({ status: 'idle' })
  const [selectedIP, setSelectedIP] = useState<string | null>(null)
  const [maxHops, setMaxHops] = useState(DEFAULT_MAX_HOPS)
  const [queries, setQueries] = useState(DEFAULT_QUERIES)
  const [timeoutMs, setTimeoutMs] = useState(DEFAULT_TIMEOUT_MS)
  const [protocol, setProtocol] = useState<Protocol>('icmp')
  const [portInputs, setPortInputs] = useState<Record<'tcp' | 'udp', string>>({
    tcp: String(DEFAULT_PORTS.tcp),
    udp: String(DEFAULT_PORTS.udp),
  })

  const [job, setJob] = useState<Job | null>(null)
  const [jobLoading, setJobLoading] = useState(false)
  const [jobFromHistory, setJobFromHistory] = useState(false)
  const [view, setView] = useState<ViewMode>('detailed')
  const [highlight, setHighlight] = useState<{ nodeId: string; ttl: number } | null>(null)
  const [startBusy, setStartBusy] = useState(false)
  const [cancelBusy, setCancelBusy] = useState(false)
  const [exportBusy, setExportBusy] = useState(false)

  const [history, setHistory] = useState<JobListItem[]>([])
  const [historyBusy, setHistoryBusy] = useState(false)
  const [historyError, setHistoryError] = useState<ApiError | null>(null)

  const [toasts, setToasts] = useState<ToastItem[]>([])
  const toastSeq = useRef(0)
  const highlightTimer = useRef<number | null>(null)
  const refreshedTerminalJob = useRef<string | null>(null)
  const resultsRef = useRef<HTMLDivElement | null>(null)

  const session = boot.status === 'ready' ? boot.session : null
  const limits = session?.limits
  const maxNodesPerJob = Math.max(1, limits?.max_nodes_per_job ?? 8)
  const maxHistoryJobs = Math.max(1, limits?.max_history_jobs ?? 200)
  const historyLimit = Math.min(HISTORY_PAGE_LIMIT, maxHistoryJobs, 100)
  const availableProtocols = useMemo(() => normalizeProtocols(limits?.protocols), [limits])

  const pushToast = useCallback((kind: ToastKind, text: string) => {
    toastSeq.current += 1
    const id = toastSeq.current
    setToasts((previous) => [...previous.slice(-3), { id, kind, text }])
    window.setTimeout(() => {
      setToasts((previous) => previous.filter((toast) => toast.id !== id))
    }, 6000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts((previous) => previous.filter((toast) => toast.id !== id))
  }, [])

  const resetToAnonymous = useCallback((notice?: string) => {
    setCsrfToken(null)
    setBoot({
      status: 'anon',
      reason: notice ? 'expired' : 'unauthenticated',
      notice,
    })
    setNodes([])
    setNodesError(null)
    setSelectedNodeIds([])
    setJob(null)
    setJobFromHistory(false)
    setJobLoading(false)
    setHistory([])
    setHistoryError(null)
    setResolveState({ status: 'idle' })
    setSelectedIP(null)
    setTargetInput('')
    setView('detailed')
    setHighlight(null)
    setLoginError(null)
    setLoginBusy(false)
    setStartBusy(false)
    setCancelBusy(false)
    setExportBusy(false)
  }, [])

  const expireSession = useCallback(() => {
    pushToast('warn', 'Your session expired. Sign in again to continue.')
    resetToAnonymous('Your session expired. Sign in again to continue.')
  }, [pushToast, resetToAnonymous])

  const checkSession = useCallback(async () => {
    setBoot({ status: 'loading' })
    try {
      const next = await fetchSession()
      setBoot({ status: 'ready', session: next })
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        setBoot({ status: 'anon', reason: 'unauthenticated' })
      } else {
        setBoot({ status: 'error', message: toApiError(error).message })
      }
    }
  }, [])

  useEffect(() => {
    void checkSession()
  }, [checkSession])

  const loadNodes = useCallback(async () => {
    setNodesBusy(true)
    setNodesError(null)
    try {
      const response = await listNodes()
      setNodes(response.nodes)
      setSelectedNodeIds((previous) => {
        const usable = new Set(
          response.nodes.filter((node) => node.enabled).map((node) => node.id),
        )
        return previous.filter((id) => usable.has(id)).slice(0, maxNodesPerJob)
      })
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
        return
      }
      setNodesError(toApiError(error))
    } finally {
      setNodesBusy(false)
    }
  }, [expireSession, maxNodesPerJob])

  const loadHistory = useCallback(async () => {
    setHistoryBusy(true)
    setHistoryError(null)
    try {
      const response = await listJobs(historyLimit)
      setHistory(response.jobs)
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
        return
      }
      setHistoryError(toApiError(error))
    } finally {
      setHistoryBusy(false)
    }
  }, [expireSession, historyLimit])

  useEffect(() => {
    if (!session) return
    void loadNodes()
    void loadHistory()
  }, [session, loadNodes, loadHistory])

  useEffect(() => {
    if (!session) return
    const serverLimits = session.limits
    setMaxHops((value) => clamp(value, 1, Math.max(1, serverLimits.max_hops)))
    setQueries((value) => clamp(value, 1, Math.max(1, serverLimits.max_queries)))
    setTimeoutMs((value) =>
      clamp(
        value,
        Math.min(serverLimits.min_execution_ms, serverLimits.max_execution_ms),
        Math.max(serverLimits.min_execution_ms, serverLimits.max_execution_ms),
      ),
    )
  }, [session])

  useEffect(() => {
    setProtocol((previous) =>
      availableProtocols.includes(previous) ? previous : (availableProtocols[0] ?? 'icmp'),
    )
  }, [availableProtocols])

  const handleLogin = useCallback(
    async (password: string) => {
      setLoginBusy(true)
      setLoginError(null)
      try {
        const next = await login(password)
        setBoot({ status: 'ready', session: next })
      } catch (error) {
        setLoginError(error instanceof ApiError ? error : toApiError(error))
      } finally {
        setLoginBusy(false)
      }
    },
    [],
  )

  const handleLogout = useCallback(async () => {
    setLogoutBusy(true)
    try {
      await logout()
    } catch (error) {
      if (!(error instanceof ApiError && (error.status === 401 || error.status === 404))) {
        pushToast('error', `Sign out failed: ${toApiError(error).message}`)
      }
    } finally {
      setLogoutBusy(false)
      resetToAnonymous()
    }
  }, [pushToast, resetToAnonymous])

  const handleResolve = useCallback(async () => {
    const target = targetInput.trim()
    if (target.length === 0) {
      pushToast('warn', 'Enter an IPv4/IPv6 address or a domain first.')
      return
    }
    setResolveState({ status: 'loading' })
    setSelectedIP(null)
    try {
      const data = await resolveTarget(target)
      const single = data.addresses.length === 1
      setSelectedIP(!data.requires_selection && single ? (data.addresses[0]?.ip ?? null) : null)
      setResolveState({ status: 'success', data })
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
        return
      }
      setResolveState({ status: 'error', error: toApiError(error) })
    }
  }, [expireSession, pushToast, targetInput])

  const handleTargetInput = useCallback((value: string) => {
    setTargetInput(value)
    setSelectedIP(null)
    setResolveState((previous) => (previous.status === 'idle' ? previous : { status: 'idle' }))
  }, [])

  const handleToggleNode = useCallback((id: string) => {
    setSelectedNodeIds((previous) => {
      if (previous.includes(id)) return previous.filter((value) => value !== id)
      if (previous.length >= maxNodesPerJob) return previous
      return [...previous, id]
    })
  }, [maxNodesPerJob])

  const handleSelectAllNodes = useCallback(() => {
    const enabled = nodes.filter((node) => node.enabled).map((node) => node.id)
    if (enabled.length > maxNodesPerJob) {
      pushToast(
        'warn',
        `Selected the first ${maxNodesPerJob} enabled agents — the controller limits one job to ${maxNodesPerJob} nodes.`,
      )
    }
    setSelectedNodeIds(enabled.slice(0, maxNodesPerJob))
  }, [maxNodesPerJob, nodes, pushToast])

  const handleClearNodes = useCallback(() => {
    setSelectedNodeIds([])
  }, [])

  const handleProtocolChange = useCallback((next: Protocol) => {
    setProtocol(next)
  }, [])

  const handlePortInputChange = useCallback(
    (value: string) => {
      if (protocol !== 'tcp' && protocol !== 'udp') return
      setPortInputs((previous) => ({ ...previous, [protocol]: value }))
    },
    [protocol],
  )

  const requiresPort = protocolRequiresPort(protocol)
  const activePortInput = protocol === 'tcp' || protocol === 'udp' ? portInputs[protocol] : ''
  const portError = requiresPort ? validatePortInput(activePortInput) : null
  const destinationPort = requiresPort && portError === null ? parsePortInput(activePortInput) : null

  const startBlockReason = useMemo(() => {
    if (!session) return 'Session unavailable.'
    if (job && !isTerminalJob(job.status)) {
      return 'A trace is already running. Cancel it in step 03 or wait for it to finish.'
    }
    if (resolveState.status !== 'success') return 'Resolve a target in step 01 first.'
    if (!selectedIP) return 'Select one resolved destination address in step 01.'
    if (selectedNodeIds.length === 0) return 'Select at least one agent in step 02.'
    if (selectedNodeIds.length > maxNodesPerJob) {
      return `Select at most ${maxNodesPerJob} agents per job.`
    }
    if (!availableProtocols.includes(protocol)) {
      return 'The selected probe protocol is not enabled by the controller.'
    }
    if (requiresPort && portError) return portError
    if (requiresPort && destinationPort == null) return 'Enter a destination port between 1 and 65535.'
    if (maxHops < 1 || maxHops > session.limits.max_hops) {
      return `Max hops must be between 1 and ${session.limits.max_hops}.`
    }
    if (queries < 1 || queries > session.limits.max_queries) {
      return `Queries must be between 1 and ${session.limits.max_queries}.`
    }
    return null
  }, [
    session,
    job,
    resolveState,
    selectedIP,
    selectedNodeIds,
    maxNodesPerJob,
    availableProtocols,
    protocol,
    requiresPort,
    portError,
    destinationPort,
    maxHops,
    queries,
  ])

  const handleStart = useCallback(async () => {
    if (startBlockReason !== null || !selectedIP || resolveState.status !== 'success') return
    setStartBusy(true)
    try {
      const request: CreateJobRequest = {
        target_ip: selectedIP,
        original_target: resolveState.data.input || targetInput.trim(),
        node_ids: selectedNodeIds,
        protocol,
        max_hops: maxHops,
        queries,
        timeout_ms: timeoutMs,
      }
      // ICMP must omit the port field entirely; TCP/UDP require it.
      if (requiresPort && destinationPort != null) request.port = destinationPort
      const response = await createJob(request)
      setJob(response.job)
      setJobFromHistory(false)
      setView('detailed')
      setHighlight(null)
      pushToast(
        'info',
        `Trace started on ${response.job.nodes.length} agent(s) · ${probeLabel(protocol, destinationPort)}.`,
      )
      if (window.matchMedia('(max-width: 1023px)').matches) {
        window.setTimeout(() => {
          resultsRef.current?.scrollIntoView({
            behavior: preferReducedMotion() ? 'auto' : 'smooth',
            block: 'start',
          })
        }, 80)
      }
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
        return
      }
      const apiError = toApiError(error)
      pushToast('error', `Trace could not be started: ${apiError.message}`)
      if (apiError.code === 'forbidden') void loadNodes()
      if (apiError.code === 'target_rejected') {
        setResolveState({ status: 'error', error: apiError })
        setSelectedIP(null)
      }
    } finally {
      setStartBusy(false)
    }
  }, [
    expireSession,
    loadNodes,
    maxHops,
    pushToast,
    queries,
    resolveState,
    selectedIP,
    selectedNodeIds,
    startBlockReason,
    targetInput,
    timeoutMs,
    protocol,
    requiresPort,
    destinationPort,
  ])

  const refreshJob = useCallback(
    async (id: string) => {
      try {
        const response = await getJob(id)
        setJob((previous) => (previous && previous.id === id ? response.job : previous))
      } catch (error) {
        if (error instanceof ApiError && error.isUnauthorized) expireSession()
      }
    },
    [expireSession],
  )

  const handleCancel = useCallback(async () => {
    if (!job) return
    setCancelBusy(true)
    try {
      const response = await cancelJob(job.id)
      setJob(response.job)
      pushToast('info', 'Cancellation requested. Node states will update shortly.')
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
      } else if (error instanceof ApiError && error.status === 409) {
        pushToast('warn', 'This job already finished before cancellation.')
        void refreshJob(job.id)
      } else if (error instanceof ApiError && error.status === 404) {
        pushToast('warn', 'The job no longer exists in controller history.')
        void loadHistory()
      } else {
        pushToast('error', `Cancel failed: ${toApiError(error).message}`)
      }
    } finally {
      setCancelBusy(false)
    }
  }, [expireSession, job, loadHistory, pushToast, refreshJob])

  const handleExport = useCallback(async () => {
    if (!job) return
    setExportBusy(true)
    try {
      await downloadJobExport(job.id)
      pushToast('success', 'Job export downloaded.')
    } catch (error) {
      if (error instanceof ApiError && error.isUnauthorized) {
        expireSession()
      } else {
        pushToast('error', `Export failed: ${toApiError(error).message}`)
      }
    } finally {
      setExportBusy(false)
    }
  }, [expireSession, job, pushToast])

  const handleCopyJobJson = useCallback(async () => {
    if (!job) return
    const ok = await copyText(JSON.stringify(job, null, 2))
    pushToast(
      ok ? 'success' : 'error',
      ok ? 'Job JSON copied to clipboard.' : 'Could not copy — clipboard is unavailable.',
    )
  }, [job, pushToast])

  const openHistoryJob = useCallback(
    async (id: string) => {
      if (job?.id === id && !jobLoading) {
        setJobFromHistory(true)
        return
      }
      setJobLoading(true)
      try {
        const response = await getJob(id)
        setJob(response.job)
        setJobFromHistory(true)
        setView('detailed')
        setHighlight(null)
      } catch (error) {
        if (error instanceof ApiError && error.isUnauthorized) {
          expireSession()
        } else if (error instanceof ApiError && error.status === 404) {
          pushToast('warn', 'Job not found — controller history may have been trimmed.')
          void loadHistory()
        } else {
          pushToast('error', `Could not open job: ${toApiError(error).message}`)
        }
      } finally {
        setJobLoading(false)
      }
    },
    [expireSession, job?.id, jobLoading, loadHistory, pushToast],
  )

  const handleJump = useCallback((nodeId: string, ttl: number) => {
    setView('detailed')
    setHighlight({ nodeId, ttl })
    if (highlightTimer.current !== null) window.clearTimeout(highlightTimer.current)
    highlightTimer.current = window.setTimeout(() => {
      setHighlight(null)
    }, HIGHLIGHT_MS)
  }, [])

  useEffect(() => {
    return () => {
      if (highlightTimer.current !== null) window.clearTimeout(highlightTimer.current)
    }
  }, [])

  const handleLiveJob = useCallback((next: Job) => {
    setJob((previous) => (previous && previous.id === next.id ? next : previous))
  }, [])

  const liveMode = useJobLive(job, {
    onJob: handleLiveJob,
    onSessionExpired: expireSession,
    onTransportError: (message) => pushToast('warn', message),
  })

  const jobTerminal = job != null && isTerminalJob(job.status)

  useEffect(() => {
    if (!job || !jobTerminal) return
    if (refreshedTerminalJob.current === job.id) return
    refreshedTerminalJob.current = job.id
    void loadHistory()
  }, [job, jobTerminal, loadHistory])

  const selectedNodeSet = useMemo(() => new Set(selectedNodeIds), [selectedNodeIds])

  const sessionWarnings = useMemo(
    () => (session?.warnings ?? []).filter((warning) => warning.trim().length > 0),
    [session],
  )

  const statusAnnouncement = job
    ? `Job ${shortId(job.id)} is ${jobStatusMeta(job.status).label}. ${job.summary.completed} of ${job.summary.total} nodes completed, ${job.summary.reached} reached the destination.`
    : ''

  const toastsView = <Toasts items={toasts} onDismiss={dismissToast} />

  if (boot.status === 'loading') {
    return (
      <>
        <BootScreen />
        {toastsView}
      </>
    )
  }

  if (boot.status === 'error') {
    return (
      <>
        <BootErrorScreen
          message={boot.message}
          busy={false}
          onRetry={() => {
            void checkSession()
          }}
        />
        {toastsView}
      </>
    )
  }

  if (boot.status === 'anon') {
    return (
      <>
        <LoginScreen
          expiredNotice={boot.reason === 'expired' ? (boot.notice ?? null) : null}
          error={loginError}
          busy={loginBusy}
          onLogin={(password) => {
            void handleLogin(password)
          }}
          onRetrySession={() => {
            void checkSession()
          }}
        />
        {toastsView}
      </>
    )
  }

  const activeSession = boot.session

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:border focus:border-accent focus:bg-ink-850 focus:px-3 focus:py-2 focus:font-mono focus:text-[12px] focus:text-fg"
      >
        Skip to main content
      </a>

      <Header session={activeSession} onLogout={() => void handleLogout()} logoutBusy={logoutBusy} />

      {sessionWarnings.length > 0 ? (
        <div role="status" className="border-b border-warn/25 bg-warn/[0.05]">
          <div className="mx-auto max-w-[1680px] px-3 py-1.5 sm:px-4">
            <ul className="space-y-0.5">
              {sessionWarnings.map((warning, index) => (
                <li
                  key={index}
                  className="flex items-start gap-1.5 text-[11px] leading-snug text-warn"
                >
                  <span aria-hidden="true" className="font-mono">
                    !
                  </span>
                  {warning}
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}

      <main id="main" className="mx-auto max-w-[1680px] px-3 pb-16 pt-3 sm:px-4">
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[340px_minmax(0,1fr)] xl:grid-cols-[350px_minmax(0,1fr)_300px]">
          <aside
            className="min-w-0 space-y-3 xl:self-start lg:sticky lg:top-[68px] lg:max-h-[calc(100vh-80px)] lg:overflow-y-auto lg:pr-0.5"
            aria-label="Trace setup"
          >
            <TargetPanel
              input={targetInput}
              onInputChange={handleTargetInput}
              state={resolveState}
              selectedIP={selectedIP}
              onSelect={setSelectedIP}
              onResolve={() => void handleResolve()}
              onRetry={() => void handleResolve()}
              maxAddresses={activeSession.limits.max_addresses}
            />

            <AgentPanel
              nodes={nodes}
              loading={nodesBusy}
              error={nodesError}
              selectedIds={selectedNodeSet}
              maxNodes={maxNodesPerJob}
              onToggle={handleToggleNode}
              onSelectAll={handleSelectAllNodes}
              onClear={handleClearNodes}
              onRefresh={() => void loadNodes()}
            />

            <RunPanel
              limits={activeSession.limits}
              protocols={availableProtocols}
              protocol={protocol}
              onProtocolChange={handleProtocolChange}
              portInput={activePortInput}
              portError={portError}
              onPortInputChange={handlePortInputChange}
              maxHops={maxHops}
              queries={queries}
              timeoutMs={timeoutMs}
              onMaxHops={(value) =>
                setMaxHops(clamp(value, 1, Math.max(1, activeSession.limits.max_hops)))
              }
              onQueries={(value) =>
                setQueries(clamp(value, 1, Math.max(1, activeSession.limits.max_queries)))
              }
              onTimeout={setTimeoutMs}
              destination={selectedIP}
              selectedNodeCount={selectedNodeIds.length}
              startBlockReason={startBlockReason}
              startBusy={startBusy}
              onStart={() => void handleStart()}
              activeJobId={job?.id ?? null}
              activeJobStatus={job?.status ?? null}
              cancelBusy={cancelBusy}
              onCancel={() => void handleCancel()}
            />
          </aside>

          <section ref={resultsRef} aria-label="Trace results" className="min-w-0 space-y-3 scroll-mt-16">
            {jobLoading ? <JobPanelSkeleton /> : null}

            {!jobLoading && job ? (
              <JobPanel
                job={job}
                liveMode={liveMode}
                view={view}
                onViewChange={setView}
                onExport={() => void handleExport()}
                exportBusy={exportBusy}
                onCopyJson={() => void handleCopyJobJson()}
                onJump={handleJump}
                highlight={highlight}
                fromHistory={jobFromHistory}
              />
            ) : null}

            {!jobLoading && !job ? (
              <div className="space-y-3">
                <section className="panel px-4 py-5" aria-labelledby="empty-heading">
                  <div className="flex items-start gap-3">
                    <span className="mt-0.5 shrink-0 text-accent/80">
                      <IconNetwork className="h-6 w-6" />
                    </span>
                    <div className="min-w-0">
                      <h2
                        id="empty-heading"
                        className="font-mono text-[13px] font-semibold uppercase tracking-[0.16em] text-fg"
                      >
                        No trace in flight
                      </h2>
                      <p className="mt-1 max-w-prose text-[12px] leading-relaxed text-muted">
                        Resolve a target, pick the exact numeric destination, and select agents.
                        Each agent runs one one-shot ICMP/TCP/UDP trace and returns its full hop
                        table.
                      </p>
                      <ol className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
                        {[
                          ['01', 'Resolve', 'Choose one IPv4/IPv6 address; multiple results need an explicit pick.'],
                          ['02', 'Select agents', 'Health and location come from the controller; disabled agents cannot run.'],
                          ['03', 'Start & compare', 'Switch to Compare for aligned TTL rows and honest ASN/latency deltas.'],
                        ].map(([step, title, text]) => (
                          <li
                            key={step}
                            className="rounded border border-line bg-ink-950/40 px-2.5 py-2"
                          >
                            <p className="font-mono text-[9px] uppercase tracking-wider text-accent/80">
                              step {step}
                            </p>
                            <p className="mt-0.5 text-[12px] font-medium text-fg-soft">{title}</p>
                            <p className="mt-0.5 text-[10px] leading-snug text-dim">{text}</p>
                          </li>
                        ))}
                      </ol>
                      <p className="mt-3 border-t border-line/70 pt-2 font-mono text-[10px] text-dim">
                        ICMP · TCP · UDP · no hop-by-hop live streaming · no silent retries
                      </p>
                    </div>
                  </div>
                </section>

                <InfoNote tone="info" title="Reading results">
                  <ul className="space-y-1 text-[11px] leading-snug">
                    <li>
                      A dashed <span className="font-mono text-muted">no reply</span> hop is an
                      unanswered probe — intermediate routers often drop them. It does not prove a
                      broken route; only an observed destination reply is conclusion-worthy.
                    </li>
                    <li>
                      ASN colors are deterministic: the same AS always receives the same hue in
                      tables, AS paths and comparisons. Hover or tap a path chip to jump to its hop
                      row.
                    </li>
                    <li>
                      Session limits, agent health and history all come from the controller. The
                      browser never resolves a name and never contacts an agent directly.
                    </li>
                  </ul>
                </InfoNote>
              </div>
            ) : null}
          </section>

          <aside
            className="min-w-0 space-y-3 lg:col-span-2 xl:col-span-1 xl:self-start xl:sticky xl:top-[68px] xl:max-h-[calc(100vh-80px)] xl:overflow-y-auto"
            aria-label="History"
          >
            <HistoryPanel
              jobs={history}
              loading={historyBusy}
              error={historyError}
              activeJobId={job?.id ?? null}
              onOpen={(id) => void openHistoryJob(id)}
              onRefresh={() => void loadHistory()}
              limit={historyLimit}
            />

            {selectedIP ? (
              <section className="panel px-3 py-2.5" aria-labelledby="selection-summary-heading">
                <div className="flex items-start justify-between gap-2">
                  <h2
                    id="selection-summary-heading"
                    className="micro"
                  >
                    Current request
                  </h2>
                  <CopyButton value={selectedIP} label="Copy selected destination" text="copy ip" />
                </div>
                <p className="mt-1 break-all font-mono text-[12px] text-accent">{selectedIP}</p>
                <p className="mt-1 flex flex-wrap items-baseline gap-x-1.5 text-[10px] text-muted">
                  <span className="badge badge-square border-accent/35 bg-accent/10 text-accent">
                    {probeLabel(protocol, destinationPort)}
                  </span>
                  <span>
                    {selectedNodeIds.length} agent{selectedNodeIds.length === 1 ? '' : 's'}
                  </span>
                  <span aria-hidden="true" className="text-dim">
                    ·
                  </span>
                  <span>{maxHops} hops</span>
                  <span aria-hidden="true" className="text-dim">
                    ·
                  </span>
                  <span>{queries}× probes</span>
                  <span aria-hidden="true" className="text-dim">
                    ·
                  </span>
                  <span>{formatSeconds(timeoutMs)}</span>
                </p>
                <p className="mt-1 font-mono text-[9px] text-dim">
                  {requiresPort
                    ? `agents probe ${protocol} destination port ${destinationPort ?? '—'} on this IP`
                    : 'agents send ICMP echo probes to only this numeric destination'}
                </p>
              </section>
            ) : null}
          </aside>
        </div>
      </main>

      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {statusAnnouncement}
      </div>

      {toastsView}
    </div>
  )
}
