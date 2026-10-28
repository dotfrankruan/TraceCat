import { useId } from 'react'
import type { FormEvent } from 'react'
import type { ResolvedAddress } from '../api/types'
import type { ResolveState } from '../types'
import { nonEmptyStrings } from '../lib/format'
import { IconArrowRight, IconInfo, IconSearch, IconTarget } from './Icons'
import { CopyButton, ErrorNote, Skeleton, Spinner } from './ui'

function AddressGroup({
  legend,
  addresses,
  selectedIP,
  radioName,
  onSelect,
}: {
  legend: string
  addresses: ResolvedAddress[]
  selectedIP: string | null
  radioName: string
  onSelect: (ip: string) => void
}) {
  if (addresses.length === 0) return null
  return (
    <fieldset className="min-w-0">
      <legend className="micro mb-1.5 flex items-center gap-1.5">
        <span className="text-fg-soft">{legend}</span>
        <span className="text-dim">· {addresses.length}</span>
      </legend>
      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        {addresses.map((address) => {
          const checked = selectedIP === address.ip
          return (
            <label
              key={address.ip}
              className={`group flex cursor-pointer items-start gap-2 rounded border px-2 py-1.5 transition-colors ${
                checked
                  ? 'border-accent/70 bg-accent/[0.08]'
                  : 'border-line bg-ink-950/50 hover:border-line-strong hover:bg-ink-850/60'
              }`}
            >
              <input
                type="radio"
                name={radioName}
                value={address.ip}
                checked={checked}
                onChange={() => onSelect(address.ip)}
                className="radio-input mt-1 shrink-0"
              />
              <span className="min-w-0 flex-1">
                <span
                  className={`block break-all font-mono text-[12px] leading-snug ${
                    checked ? 'text-fg' : 'text-fg-soft'
                  }`}
                >
                  {address.ip}
                </span>
                <span className="mt-0.5 block font-mono text-[9px] uppercase tracking-wider text-dim">
                  {address.family === 'ipv6' ? 'IPv6' : 'IPv4'}
                </span>
              </span>
              <CopyButton
                value={address.ip}
                label={`Copy address ${address.ip}`}
                className="mt-0.5 shrink-0"
              />
            </label>
          )
        })}
      </div>
    </fieldset>
  )
}

export function TargetPanel({
  input,
  onInputChange,
  state,
  selectedIP,
  onSelect,
  onResolve,
  onRetry,
  maxAddresses,
  disabled = false,
}: {
  input: string
  onInputChange: (value: string) => void
  state: ResolveState
  selectedIP: string | null
  onSelect: (ip: string) => void
  onResolve: () => void
  onRetry: () => void
  maxAddresses: number
  disabled?: boolean
}) {
  const radioName = useId()
  const inputId = useId()
  const loading = state.status === 'loading'
  const data = state.status === 'success' ? state.data : null
  const ipv4 = data?.addresses.filter((address) => address.family === 'ipv4') ?? []
  const ipv6 = data?.addresses.filter((address) => address.family === 'ipv6') ?? []
  const multiple = (data?.addresses.length ?? 0) > 1
  const warnings = nonEmptyStrings(data?.warnings)

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault()
    onResolve()
  }

  return (
    <section className="panel" aria-labelledby="target-heading">
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-3 py-2">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] leading-none text-accent/80">01</span>
            <h2
              id="target-heading"
              className="font-mono text-[11px] font-semibold uppercase leading-none tracking-[0.16em] text-fg-soft"
            >
              Target
            </h2>
          </div>
          <p className="mt-1 text-[11px] text-muted">
            IPv4, IPv6 or domain · resolved by the controller
          </p>
        </div>
        <IconTarget className="mt-0.5 h-4 w-4 shrink-0 text-dim" />
      </header>

      <div className="px-3 py-2.5">
        <form onSubmit={handleSubmit} className="flex items-stretch gap-1.5">
          <div className="min-w-0 flex-1">
            <label htmlFor={inputId} className="sr-only">
              Trace target: IPv4, IPv6 address or domain name
            </label>
            <input
              id={inputId}
              className="input"
              type="text"
              inputMode="text"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="example.com or 2001:db8::10"
              value={input}
              onChange={(event) => onInputChange(event.target.value)}
              disabled={disabled}
              aria-describedby={`${inputId}-help`}
            />
          </div>
          <button
            type="submit"
            className="btn btn-ghost shrink-0"
            disabled={loading || disabled || input.trim().length === 0}
            aria-label="Resolve target on the controller"
          >
            {loading ? <Spinner className="h-3.5 w-3.5" /> : <IconSearch className="h-3.5 w-3.5" />}
            {loading ? 'Resolving' : 'Resolve'}
          </button>
        </form>
        <p id={`${inputId}-help`} className="mt-1.5 text-[10px] leading-snug text-dim">
          Only IP literals and domains are accepted. Resolution happens on the controller — agents
          never resolve names and this page never parses URLs.
        </p>

        {state.status === 'loading' ? (
          <div className="mt-3 space-y-1.5" aria-hidden="true">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : null}

        {state.status === 'error' ? (
          <div className="mt-3">
            <ErrorNote error={state.error} onRetry={onRetry} retryLabel="Resolve again" />
          </div>
        ) : null}

        {data ? (
          <div className="mt-3 space-y-2.5">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-line/70 pb-2">
              <span className="badge badge-square border-line-strong text-muted">
                {data.kind === 'ip'
                  ? 'IP literal'
                  : data.kind === 'domain'
                    ? 'Domain'
                    : data.kind}
              </span>
              <span className="min-w-0 break-all font-mono text-[12px] text-fg-soft">
                {data.input}
              </span>
              <span className="ml-auto font-mono text-[10px] text-dim">
                {data.addresses.length} {data.addresses.length === 1 ? 'address' : 'addresses'}
              </span>
            </div>

            {data.truncated ? (
              <p className="rounded border border-warn/30 bg-warn/[0.055] px-2 py-1.5 text-[11px] text-warn">
                Address list was capped at {maxAddresses} entries by the controller. If the service
                is highly distributed, resolving a specific host or using an IP literal gives a
                narrower view.
              </p>
            ) : null}

            {warnings.length > 0 ? (
              <div className="rounded border border-warn/30 bg-warn/[0.055] px-2 py-1.5">
                <p className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-warn">
                  <IconInfo className="h-3 w-3" />
                  Resolution note
                </p>
                <ul className="mt-1 space-y-1">
                  {warnings.map((warning, index) => (
                    <li key={index} className="text-[11px] leading-snug text-fg-soft">
                      {warning}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {data.addresses.length === 0 ? (
              <p className="text-[12px] text-warn">
                The controller returned no usable addresses for this target.
              </p>
            ) : (
              <div className="space-y-3">
                <AddressGroup
                  legend="IPv4"
                  addresses={ipv4}
                  selectedIP={selectedIP}
                  radioName={radioName}
                  onSelect={onSelect}
                />
                <AddressGroup
                  legend="IPv6"
                  addresses={ipv6}
                  selectedIP={selectedIP}
                  radioName={radioName}
                  onSelect={onSelect}
                />
              </div>
            )}

            {data.addresses.length > 0 ? (
              <div className="rounded border border-line-strong bg-ink-950/60 px-2.5 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="micro">Destination</span>
                  {selectedIP ? (
                    <CopyButton value={selectedIP} label="Copy destination IP" text="copy ip" />
                  ) : null}
                </div>
                {selectedIP ? (
                  <>
                    <p className="mt-1 flex items-center gap-1.5 break-all font-mono text-[14px] text-accent">
                      <IconArrowRight className="h-3.5 w-3.5 shrink-0" />
                      {selectedIP}
                    </p>
                    <p className="mt-0.5 text-[10px] leading-snug text-muted">
                      Every selected agent probes this exact numeric IP.
                    </p>
                  </>
                ) : multiple ? (
                  <p className="mt-1 text-[12px] text-warn">
                    {data.addresses.length} addresses returned — choose exactly one above. TraceCat
                    never silently picks the first address.
                  </p>
                ) : (
                  <p className="mt-1 text-[12px] text-warn">No destination selected.</p>
                )}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  )
}
