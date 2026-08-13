#!/usr/bin/env bash
# Resolves the manifest digest for a public image:tag via each registry's
# anonymous pull-token flow, so a deploy can pin by digest (immune to a tag
# being silently repointed at different content) without hardcoding per-tag
# digests that go stale. Requests the multi-arch index digest specifically
# (not a single-platform manifest), so pinning doesn't break portability
# across architectures.
#
# Usage: resolve-image-digest.sh <registry-host> <repository> <tag>
#   registry-host: registry-1.docker.io | ghcr.io
set -euo pipefail

REGISTRY="${1:?usage: resolve-image-digest.sh <registry-host> <repository> <tag>}"
REPOSITORY="${2:?usage: resolve-image-digest.sh <registry-host> <repository> <tag>}"
TAG="${3:?usage: resolve-image-digest.sh <registry-host> <repository> <tag>}"

log() { echo "[resolve-image-digest] $*" >&2; }

case "$REGISTRY" in
  registry-1.docker.io)
    AUTH_URL="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPOSITORY}:pull"
    ;;
  ghcr.io)
    AUTH_URL="https://ghcr.io/token?service=ghcr.io&scope=repository:${REPOSITORY}:pull"
    ;;
  *)
    log "ERROR: unsupported registry: $REGISTRY"
    exit 1
    ;;
esac

token="$(curl -sf "$AUTH_URL" | grep -oP '"token":"\K[^"]+')" || {
  log "ERROR: failed to fetch auth token from $AUTH_URL"
  exit 1
}

if [ -z "$token" ]; then
  log "ERROR: empty auth token from $AUTH_URL"
  exit 1
fi

digest="$(curl -sf -D - -o /dev/null \
  -H "Authorization: Bearer $token" \
  -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json" \
  "https://${REGISTRY}/v2/${REPOSITORY}/manifests/${TAG}" \
  | grep -i '^docker-content-digest:' | tr -d '\r' | awk '{print $2}')" || {
  log "ERROR: failed to fetch manifest for ${REPOSITORY}:${TAG} from $REGISTRY"
  exit 1
}

if [ -z "$digest" ]; then
  log "ERROR: no digest found in manifest response for ${REPOSITORY}:${TAG}"
  exit 1
fi

log "Resolved ${REPOSITORY}:${TAG} -> ${digest}"
echo "$digest"