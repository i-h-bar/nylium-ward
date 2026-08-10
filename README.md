# Modded Minecraft Server

A CurseForge modpack server running on Kubernetes, exposed through a
[playit.gg](https://playit.gg) tunnel — no port forwarding required.

The server image is [`itzg/minecraft-server`](https://github.com/itzg/docker-minecraft-server)
in `AUTO_CURSEFORGE` mode: it downloads the modpack, installs the matching
Forge/Fabric version, and applies the pack's config overrides on its own.
Nothing is built from source and there is no registry.

## Architecture

```
Internet → playit.gg tunnel → Service (pinned ClusterIP) → server pod → PVC
```

The playit agent runs as its own Deployment so the tunnel stays connected
while the server restarts — which matters, because a modpack upgrade can
take several minutes.

## Prerequisites

- A Kubernetes cluster (k3s) with the `local-path` storage class
- `helm`, `kubectl`, and `task` on the machine you operate from
- A [playit.gg](https://playit.gg) account with a TCP tunnel

## Setup

### 1. Choose the modpack

Edit `chart/values.yaml`:

```yaml
modpack:
  slug: all-the-mods-10     # from curseforge.com/minecraft/modpacks/<slug>
  fileId: "1234567"         # a specific file id from the pack's Files tab
```

Both are required — the chart refuses to render without them. `fileId` is
pinned on purpose so a pod restart can never silently upgrade the pack
underneath a live world. Use a modpack file that includes the pack manifest,
not a "Server Files" download.

Most packs need more than the default memory. Adjust `server.memory` and keep
`resources.limits.memory` roughly 2Gi above it.

### 2. Create `.env`

```bash
cp .env.example .env
```

Fill in `PLAYIT_SECRET_KEY` from the playit.gg dashboard. `CF_API_KEY` is
optional — the image bundles a working key.

### 3. Deploy

```bash
task up
```

First boot downloads the entire modpack and generates a world, so it can take
10+ minutes. Watch it with `task logs`.

### 4. Point the tunnel at the server

In the playit.gg dashboard, set the tunnel's local destination to the pinned
Service address:

```
10.43.255.65:25565
```

That value comes from `service.clusterIP` in `chart/values.yaml`. It is pinned
so you only ever set it once.

## Operations

| Command | What it does |
|---|---|
| `task up` | Install or upgrade, waiting for readiness |
| `task down` | Uninstall (the world PVC is kept) |
| `task status` | Pods, PVC, and service state |
| `task logs` | Stream server logs |
| `task console` | RCON console — run `list`, `op <player>`, etc. |
| `task restart` | Restart the server pod |
| `task secrets` | Re-apply the secret after editing `.env` |
| `task export` | Snapshot the world to `exports/` |
| `task restore FILE=…` | Replace the world from a snapshot |
| `task upgrade` | Apply a new pinned `fileId` (snapshots first) |

## Upgrading the modpack

1. Edit `modpack.fileId` in `chart/values.yaml` and commit it.
2. Run `task upgrade`.

It exports the world before touching anything. If the upgrade goes badly,
`task restore FILE=exports/world-<newest>.tar.gz` puts the world back.

`helm rollback` reverts manifests only — it does **not** revert the world or
the installed mods. Use `task restore`.

## Giving someone their world

```bash
task export
```

Writes `exports/world-<timestamp>.tar.gz`. It is safe on a running server:
saving is paused, everything is flushed to disk, the archive is taken, and
saving is re-enabled. The archive includes a `PACK.txt` naming the modpack
slug and file id, since a modded world needs the identical pack build to open.

## Notes

- RCON needs no configuration. It is enabled by default, the image generates
  a password, and it is never exposed outside the pod — `task console` reaches
  it through `kubectl exec`.
- `task down` keeps the world. To delete it deliberately:
  `kubectl delete pvc minecraft-data`.
- Everything deploys to the `default` namespace.
- By using this project you accept the
  [Minecraft EULA](https://www.minecraft.net/eula).