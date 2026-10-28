import type { SVGProps } from 'react'

type IconProps = SVGProps<SVGSVGElement>

function baseProps(props: IconProps): IconProps {
  return {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round',
    strokeLinejoin: 'round',
    width: 16,
    height: 16,
    'aria-hidden': true,
    focusable: 'false',
    ...props,
  }
}

export function IconLogo({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={28}
      height={28}
      className={className}
      role="img"
      aria-label="TraceCat"
    >
      <path
        d="M8 12.5 9.5 7l4.5 3.5h4L22.5 7l1.5 5.5V22a6 6 0 0 1-6 6h-4a6 6 0 0 1-6-6V12.5Z"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.8}
        strokeLinejoin="round"
      />
      <circle cx="12.5" cy="17" r="1.4" fill="#34d399" />
      <circle cx="19.5" cy="17" r="1.4" fill="#f472b6" />
      <path
        d="M2 25.5h5.5M24.5 25.5H30M2 28h3.5M26.5 28H30"
        stroke="#fbbf24"
        strokeWidth={1.4}
        strokeLinecap="round"
        opacity={0.8}
      />
    </svg>
  )
}

export function IconChevronDown(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  )
}

export function IconChevronRight(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  )
}

export function IconArrowRight(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M4 12h16M14 6l6 6-6 6" />
    </svg>
  )
}

export function IconCopy(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h9" />
    </svg>
  )
}

export function IconCheck(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="m4 12.5 5 5L20 6.5" />
    </svg>
  )
}

export function IconClose(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="m6 6 12 12M18 6 6 18" />
    </svg>
  )
}

export function IconRefresh(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M20 11a8 8 0 1 0-2.3 6.4" />
      <path d="M20 4v7h-7" />
    </svg>
  )
}

export function IconDownload(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M12 3v12M7 10l5 5 5-5" />
      <path d="M4 17v3h16v-3" />
    </svg>
  )
}

export function IconPlay(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M7 4.5 19 12 7 19.5v-15Z" />
    </svg>
  )
}

export function IconStop(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <rect x="6" y="6" width="12" height="12" rx="1.5" />
    </svg>
  )
}

export function IconTarget(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
    </svg>
  )
}

export function IconServer(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </svg>
  )
}

export function IconHistory(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M3.5 12a8.5 8.5 0 1 0 2.8-6.3" />
      <path d="M3 4v5h5" />
      <path d="M12 8v4.5l3 2" />
    </svg>
  )
}

export function IconAlert(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M12 3.5 21 19H3L12 3.5Z" />
      <path d="M12 10v4M12 17.2h.01" />
    </svg>
  )
}

export function IconInfo(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </svg>
  )
}

export function IconNoReply(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <circle cx="12" cy="12" r="8" strokeDasharray="2.5 3" />
      <path d="M12 8v4M12 16h.01" />
    </svg>
  )
}

export function IconExternal(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M14 4h6v6" />
      <path d="M20 4 11 13" />
      <path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />
    </svg>
  )
}

export function IconLock(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
  )
}

export function IconLogout(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4" />
      <path d="M15 8l4 4-4 4M19 12H9" />
    </svg>
  )
}

export function IconNetwork(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <circle cx="5" cy="6" r="2.2" />
      <circle cx="19" cy="6" r="2.2" />
      <circle cx="12" cy="18" r="2.2" />
      <path d="M7.2 6h9.6M6.2 8l4.4 7.9M17.8 8l-4.4 7.9" />
    </svg>
  )
}

export function IconSearch(props: IconProps) {
  return (
    <svg {...baseProps(props)}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </svg>
  )
}
