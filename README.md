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

- A Kubernetes cluster (k3s) with the `local-path` storage class and
  [Cilium](https://cilium.io) as its CNI — `./scripts/setup.sh` sets both up
- `helm`, `kubectl`, and `task` on the machine you operate from
- A [playit.gg](https://playit.gg) account with a TCP tunnel

Run `./scripts/setup.sh` to install k3s, Helm, and Task in one shot. It
auto-detects the OS (Debian/Ubuntu and Arch/CachyOS today; see
`scripts/setup/` to add more) or takes a target explicitly:
`./scripts/setup.sh debian`.

On Windows, run it inside WSL2 (Ubuntu) rather than natively — k3s needs a
Linux kernel. WSL doesn't enable systemd by default, which k3s requires; if
it's off, add to `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

then run `wsl --shutdown` from Windows and reopen the distro before running
the script.

## Setup

### 1. Choose the modpack

Find the pack on CurseForge and take two values from its URLs. Using
[All the Mods 10](https://www.curseforge.com/minecraft/modpacks/all-the-mods-10)
as an example:

1. **`slug`** — the path segment right after `/minecraft/modpacks/` in the
   pack's main page URL:
   `curseforge.com/minecraft/modpacks/`**`all-the-mods-10`**

2. **`fileId`** — open the pack's **Files** tab
   (`.../all-the-mods-10/files/all`), which lists every release. That list
   does **not** show the ID — click into the specific version you want. Its
   page URL ends in the numeric ID:
   `curseforge.com/minecraft/modpacks/all-the-mods-10/files/`**`8558519`**

Then edit `chart/values.yaml`:

```yaml
modpack:
  slug: all-the-mods-10
  fileId: "8558519"
```

Both are required — the chart refuses to render without them. `fileId` is
pinned on purpose so a pod restart can never silently upgrade the pack
underneath a live world. Use a modpack file that includes the pack manifest,
not a "Server Files" download.

Most packs need more than the default memory. Adjust `server.memory` and keep
`resources.limits.memory` roughly 2Gi above it.

### 2. (Optional) Add a resource pack

A resource pack is a texture/UI pack the server pushes to every client on
join. To enable one, edit `chart/values.yaml`:

```yaml
resourcePack:
  url: https://example.com/my-pack.zip   # must be a direct .zip link
  sha1: ""                                # optional but recommended checksum
  enforce: false                          # true kicks clients who decline it
```

Leave `url` empty to disable it entirely — the default.

### 3. Create `.env`

```bash
cp .env.example .env
```

Fill in `PLAYIT_SECRET_KEY` from the playit.gg dashboard. `CF_API_KEY` is
optional — the image bundles a working key.

### 4. Deploy

```bash
task up
```

First boot downloads the entire modpack and generates a world, so it can take
10+ minutes. Watch it with `task logs`.

### 5. Point the tunnel at the server

In the playit.gg dashboard, set the tunnel's local destination to the pinned
Service address:

```
10.43.255.65:25565
```

That value comes from `service.clusterIP` in `chart/values.yaml`. It is pinned
so you only ever set it once.

## Network security

Cilium enforces `CiliumNetworkPolicy` rules on both pods:

- **minecraft**: only reachable from the `playit` pod on 25565. Outbound
  traffic is default-deny except an FQDN allowlist — broad while a modpack is
  being fetched (CurseForge, Forge/Fabric, Mojang piston-meta), narrowed to
  just Mojang session-auth once the server is running. `task up`,
  `task upgrade`, and `task restart` all switch between these automatically;
  you don't need to think about it in normal use.
- **playit**: nothing can reach it at all (it only dials out). Outbound is
  broad — its relay endpoints aren't a stable, documented list to allowlist
  by domain.

If a modpack needs a domain outside the built-in list, add it to
`networkPolicy.extraAllowedFQDNs` in `chart/values.yaml`. To find out what's
being blocked, run `task cilium:audit-on` (logs drops via Hubble without
enforcing, cluster-wide) and watch with `task hubble`; run
`task cilium:audit-off` when done.

**WSL2 note:** Cilium's eBPF datapath is not an officially supported
environment under WSL2's kernel. It's expected to work but hasn't been
exhaustively verified across WSL2 kernel versions — if `task cilium:status`
never goes ready, that's the first thing to suspect.

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
| `task cilium:up` | Install or upgrade Cilium itself |
| `task cilium:status` | Cilium DaemonSet/operator rollout status |
| `task hubble` | Stream live network flows (Ctrl-C to stop) |

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