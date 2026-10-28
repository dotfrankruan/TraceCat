# TraceCat dashboard (`web/`)

The TraceCat dashboard is a static React + TypeScript single-page app. **Node.js is
build-time only.** Vite renders plain HTML/CSS/JS into `../internal/webui/public`,
which the Go controller embeds with `go:embed`. The shipped artifact is a single Go
binary: no Node process, Node server or JavaScript runtime exists at runtime.

## Build

```sh
pnpm --dir web install
pnpm --dir web typecheck      # tsc --noEmit
pnpm --dir web build          # tsc --noEmit && vite build -> internal/webui/public
```

`make ui` / `make build` run the same commands from the repository root. Vite
empties `internal/webui/public` (`emptyOutDir`) and the build script restores its
`.gitkeep` placeholder. The generated `index.html`, `assets/**` and `favicon.svg`
are committed intentionally: the Go controller embeds them, so building the
binaries needs neither Node.js nor pnpm. Re-run the dashboard build after changing
`web/` sources and commit the regenerated assets together with the source change.

## Local development

```sh
pnpm --dir web dev
```

Vite serves the dashboard at <http://127.0.0.1:5173> and proxies `/api` to the Go
controller on <http://127.0.0.1:8080> (see `vite.config.ts`). Start the controller
with `make dev-controller` first. The dashboard has no router: all state lives at
`/`, and the embedded SPA fallback is served by `internal/webui/webui.go`.

## Constraints enforced here

- Dependencies are intentionally minimal: `react`, `react-dom`, `typescript`,
  `vite`, `@vitejs/plugin-react`, `tailwindcss`, `@tailwindcss/vite`,
  `@types/react`, `@types/react-dom`. No UI kit, router, state library, chart
  library or extra CSS framework.
- Strict TypeScript (`tsc --noEmit` is part of `build`).
- Tailwind CSS v4 via `@tailwindcss/vite`; no runtime CSS framework.
- No external fonts, CDNs or images. Only self-hosted assets and inline SVG so the
  controller CSP (`self` only, no inline scripts) is satisfied.
- `dangerouslySetInnerHTML` is never used; all controller/agent metadata is rendered
  as text.
- The CSRF token returned by `GET /api/v1/session` is kept in module memory only
  (`src/api/client.ts`) and sent as `X-TraceCat-CSRF` on every POST.
- Live updates use the controller SSE stream as state-change notifications (full
  job snapshots), with a 3-second polling fallback. The UI never claims hop-by-hop
  live streaming.

## Layout

```
src/
  api/            wire types mirroring internal/model + typed fetch client
  hooks/          useJobLive (SSE + polling fallback)
  lib/            ASN colour hashing, hop derivation, formatting, clipboard
  components/     header, login, setup panels, job/results, AS path, hop table, compare, history
  App.tsx         session boot, orchestration, API error handling, toasts
```
