#!/usr/bin/env bash
set -euo pipefail

version=${1:?Usage: scripts/package.sh VERSION GOOS GOARCH}
target_os=${2:?Missing GOOS}
target_arch=${3:?Missing GOARCH}
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9.-]+)?$ ]]; then
  echo "Expected a version such as v0.1.0" >&2
  exit 1
fi
case "$target_os/$target_arch" in
  linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64|windows/arm64) ;;
  *) echo "Unsupported platform: $target_os/$target_arch" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
mkdir -p dist
archive="onesocks_${version#v}_${target_os}_${target_arch}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
package="$stage/$archive"
mkdir -p "$package/.github/assets"
binary=onesocks
[[ $target_os != windows ]] || binary=onesocks.exe
CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" "${GO:-go}" build \
  -tags with_utls -trimpath -ldflags "-s -w -X main.version=$version" \
  -o "$package/$binary" ./cmd/onesocks
cp README.md README.zh-CN.md LICENSE "$package/"
cp .github/assets/*.png "$package/.github/assets/"
cat > "$package/config.yaml" <<'YAML'
socks_listen: 127.0.0.1:1080
api_listen: 127.0.0.1:8080
data_dir: data
socks_password: ""
api_token: ""
probe_concurrency: 16
outbound_interface: ""
YAML
if [[ $target_os == windows ]]; then
  destination="$PWD/dist/$archive.zip"
  rm -f "$destination"
  (cd "$stage" && zip -qr "$destination" "$archive")
else
  tar -czf "dist/$archive.tar.gz" -C "$stage" "$archive"
fi
