#!/usr/bin/env bash
# Build TraceCat release tarballs locally (same layout as the CI release job).
#
# Usage:
#   scripts/build-release.sh [VERSION] [ARCH...]
#   scripts/build-release.sh 0.1.1 amd64 arm64
#
# Output: dist/tracecat-{controller,agent}-linux-{arch}.tar.gz + checksums.txt
# Requires the dashboard assets to be present (committed); run `make ui` first
# if you changed web/ sources. Go is the only required toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
shift || true
if [[ $# -gt 0 ]]; then
  ARCHES=("$@")
else
  ARCHES=(amd64 arm64)
fi

commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ldflags="-s -w \
  -X github.com/dotfrankruan/tracecat/internal/version.Version=${VERSION} \
  -X github.com/dotfrankruan/tracecat/internal/version.Commit=${commit} \
  -X github.com/dotfrankruan/tracecat/internal/version.BuildDate=${build_date}"

[[ -f internal/webui/public/index.html ]] || {
  echo "error: embedded dashboard assets missing; run 'make ui' first" >&2
  exit 1
}

rm -rf dist stage
mkdir -p dist stage

for arch in "${ARCHES[@]}"; do
  echo "==> linux/${arch}"
  for component in controller agent; do
    stage_dir="stage/${component}-${arch}"
    mkdir -p "$stage_dir"/{bin,configs,deploy/systemd}
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -trimpath -ldflags "$ldflags" \
      -o "$stage_dir/bin/tracecat-${component}" "./cmd/tracecat-${component}"
    cp "configs/${component}.example.json" "$stage_dir/configs/"
    cp "deploy/systemd/tracecat-${component}.service" \
       "deploy/systemd/tracecat-${component}.env.example" "$stage_dir/deploy/systemd/"
    cp deploy/install.sh QUICKSTART.md CHANGELOG.md LICENSE NOTICE README.md SECURITY.md "$stage_dir/"
    cp -r docs "$stage_dir/"
    rm -rf "$stage_dir/docs/screenshots"
    printf '%s\n' "$VERSION" >"$stage_dir/VERSION"
    tar -czf "dist/tracecat-${component}-linux-${arch}.tar.gz" -C "$stage_dir" .
  done
done

(cd dist && sha256sum tracecat-*.tar.gz >checksums.txt && cat checksums.txt)
echo
echo "release assets in $ROOT/dist"
