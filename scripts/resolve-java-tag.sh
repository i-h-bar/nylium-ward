#!/usr/bin/env bash
# Prints the itzg/minecraft-server image tag (e.g. "java17") that matches the
# Minecraft version of the pinned modpack fileId, so the chart never boots a
# Forge/NeoForge/Fabric server under the wrong JDK (Mixin's bundled ASM can't
# even read core JDK classes compiled by a too-new javac, which crashes the
# server outright instead of just misbehaving).
#
# Resolution has two paths:
#   - CF_API_KEY set in .env: resolve the Minecraft version via the
#     CurseForge API, entirely on this machine, before any cluster change.
#   - otherwise: apply the chart with the install-phase policy (whatever
#     image.tag it currently has, which may be wrong), then poll the pod for
#     /data/.install-curseforge.env, which mc-image-helper writes as soon as
#     the modpack download+extract finishes — before Forge/NeoForge ever
#     tries to boot the JVM, so it exists even on a doomed install.
#
# Either way the Minecraft version is then resolved to a required Java
# version via Mojang's own per-version manifest (the same source the real
# launcher uses), so there's no hand-maintained version-range table to keep
# up to date.
#
# Result is cached per fileId in .cache/java-tag/ so repeat runs (task
# restart, re-running task up) are instant. Delete the cache entry to force
# re-detection.
#
# Only the resolved tag is printed to stdout — everything else goes to
# stderr, since Taskfile.yaml captures this script's stdout into a var.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALUES_FILE="$REPO_ROOT/chart/values.yaml"
ENV_FILE="$REPO_ROOT/.env"
CACHE_DIR="$REPO_ROOT/.cache/java-tag"

RELEASE="${RELEASE:-minecraft}"
CHART="${CHART:-$REPO_ROOT/chart}"
DEPLOY="${DEPLOY:-deploy/minecraft}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-900}"

log() { echo "[resolve-java-tag] $*" >&2; }

fallback_tag() {
  grep -E '^\s*tag:' "$VALUES_FILE" | head -1 | sed -E 's/.*tag:\s*"?([^"[:space:]]+)"?.*/\1/' || true
}

die_with_fallback() {
  log "WARNING: $1 — falling back to configured image.tag ($(fallback_tag))"
  echo "$(fallback_tag)"
  exit 0
}

FILE_ID="$(grep -E '^\s*fileId:' "$VALUES_FILE" | head -1 | sed -E 's/.*fileId:\s*"?([0-9]+)"?.*/\1/' || true)"
if [ -z "$FILE_ID" ]; then
  die_with_fallback "could not read modpack.fileId from $VALUES_FILE"
fi

mkdir -p "$CACHE_DIR"
CACHE_FILE="$CACHE_DIR/$FILE_ID"
if [ -s "$CACHE_FILE" ]; then
  log "cache hit for fileId $FILE_ID: $(cat "$CACHE_FILE")"
  cat "$CACHE_FILE"
  exit 0
fi

CF_API_KEY=""
if [ -f "$ENV_FILE" ]; then
  CF_API_KEY="$(grep -E '^CF_API_KEY=.+' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)"
fi

mc_version_via_curseforge_api() {
  log "CF_API_KEY set — resolving Minecraft version via CurseForge API (no cluster changes yet)"
  local body response
  body="$(jq -n --argjson id "$FILE_ID" '{fileIds: [$id]}')"
  response="$(curl -sS -X POST "https://api.curseforge.com/v1/mods/files" \
    -H "x-api-key: $CF_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$body")" || return 1
  echo "$response" | jq -r '.data[0].gameVersions[]? // empty' \
    | grep -E '^[0-9]+\.[0-9]+(\.[0-9]+)?$' | head -1 || true
}

mc_version_via_poll() {
  log "No CF_API_KEY — applying install-phase policy, then polling the pod for the install manifest"
  log "(this costs one deploy cycle; the pod may crash-loop briefly if the current image.tag is wrong for this pack)"
  helm upgrade --install "$RELEASE" "$CHART" --set networkPolicy.phase=install >&2

  local waited=0
  while [ "$waited" -lt "$POLL_TIMEOUT_SECS" ]; do
    if kubectl exec "$DEPLOY" -- test -f /data/.install-curseforge.env 2>/dev/null; then
      kubectl exec "$DEPLOY" -- grep '^VERSION=' /data/.install-curseforge.env \
        | cut -d= -f2 | tr -d '"' || true
      return 0
    fi
    sleep 5
    waited=$((waited + 5))
  done
  return 1
}

MC_VERSION=""
if [ -n "$CF_API_KEY" ]; then
  MC_VERSION="$(mc_version_via_curseforge_api || true)"
  if [ -z "$MC_VERSION" ]; then
    log "WARNING: CurseForge API resolution failed despite CF_API_KEY being set — falling back to polling"
  fi
fi
if [ -z "$MC_VERSION" ]; then
  MC_VERSION="$(mc_version_via_poll || true)"
fi
if [ -z "${MC_VERSION:-}" ]; then
  die_with_fallback "could not determine the modpack's Minecraft version"
fi
log "modpack targets Minecraft $MC_VERSION"

MANIFEST="$(curl -sS "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json")" \
  || die_with_fallback "could not reach piston-meta.mojang.com"
VERSION_URL="$(echo "$MANIFEST" | jq -r --arg v "$MC_VERSION" '.versions[] | select(.id==$v) | .url' || true)"
if [ -z "$VERSION_URL" ]; then
  die_with_fallback "Mojang's manifest has no entry for Minecraft $MC_VERSION"
fi

VERSION_JSON="$(curl -sS "$VERSION_URL")" \
  || die_with_fallback "could not fetch Mojang's per-version manifest for $MC_VERSION"
JAVA_MAJOR="$(echo "$VERSION_JSON" | jq -r '.javaVersion.majorVersion // empty' || true)"
if [ -z "$JAVA_MAJOR" ]; then
  log "WARNING: Mojang manifest for $MC_VERSION has no javaVersion field (pre-1.6 version?) — assuming Java 8"
  JAVA_MAJOR=8
fi

TAG="java${JAVA_MAJOR}"
log "resolved Minecraft $MC_VERSION -> $TAG"
echo "$TAG" > "$CACHE_FILE"
echo "$TAG"