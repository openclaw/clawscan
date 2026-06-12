#!/usr/bin/env bash
set -euo pipefail

version="${1:-dev}"
commit="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dist_dir="dist"
package="github.com/openclaw/clawscan/cmd/clawscan"

platforms=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
)

rm -rf "$dist_dir"
mkdir -p "$dist_dir"

ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}"

for platform in "${platforms[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  name="clawscan_${version}_${os}_${arch}"
  workdir="${dist_dir}/${name}"
  binary="clawscan"

  if [[ "$os" == "windows" ]]; then
    binary="clawscan.exe"
  fi

  mkdir -p "$workdir"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "${workdir}/${binary}" "$package"
  cp README.md "${workdir}/README.md"

  if [[ "$os" == "windows" ]]; then
    (cd "$dist_dir" && zip -qr "${name}.zip" "$name")
  else
    (cd "$dist_dir" && tar -czf "${name}.tar.gz" "$name")
  fi
done

(cd "$dist_dir" && shasum -a 256 *.tar.gz *.zip > checksums.txt)

printf 'Built release artifacts in %s/\n' "$dist_dir"
