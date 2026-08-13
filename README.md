# Nylium Ward

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
optional — the image bundles a working key for installing the pack itself.
Setting your own (free, from the
[CurseForge Studio Console](https://console.curseforge.com/)) only changes
*when* the correct Java version gets resolved — see
[Java version](#java-version) below.

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
  scoped to playit.gg's published relay IP ranges and known control domains
  (`playit.gg`, `ply.gg`, `playit.cloud`) — not a broad allow.

If a modpack needs a domain outside the built-in list, add it to
`networkPolicy.extraAllowedFQDNs` in `chart/values.yaml`. To find out what's
being blocked, run `task cilium:audit-on` (logs drops via Hubble without
enforcing, cluster-wide) and watch with `task hubble`; run
`task cilium:audit-off` when done.

Playit's egress allowlist (which IP ranges the `playit` pod can reach) is
synced from playit.gg's published ranges via `task playit:sync-ips`. Re-run
it occasionally and commit the diff in `chart/files/playit-allowed-cidrs.txt`
— it isn't run automatically.

**WSL2 note:** Cilium's eBPF datapath is not an officially supported
environment under WSL2's kernel. It's expected to work but hasn't been
exhaustively verified across WSL2 kernel versions — if `task cilium:status`
never goes ready, that's the first thing to suspect.

## Java version

Forge/NeoForge/Fabric all bundle Mixin, which uses an ASM version too old to
even read class files compiled by a too-new JDK — booting the wrong Java
major doesn't just misbehave, it crashes the server outright. Different
modpacks (and different Minecraft versions across a pack's own updates) need
different Java majors, so `chart/values.yaml`'s `image.tag` can't be a fixed
value.

`task up`, `task upgrade`, and `task restart` all run
`scripts/resolve-java-tag.sh` before deploying, which resolves the correct
`itzg/minecraft-server` tag (`java17`, `java21`, ...) for the pinned
`modpack.fileId` and overrides `image.tag` with it — you never need to pick
this by hand. Resolution has two paths:

- **`CF_API_KEY` set in `.env`** — resolves the modpack's Minecraft version
  via the CurseForge API, on your machine, before any cluster change. The
  correct tag is applied on the very first deploy.
- **No `CF_API_KEY`** — deploys once with whatever tag is currently
  configured, then polls the pod for `/data/.install-curseforge.env`. That
  file is written by the install step as soon as the modpack download+extract
  finishes, before Forge/NeoForge ever tries to boot the JVM — so it's there
  even if the wrong Java then crashes the server. Once read, the deploy is
  redone with the corrected tag. This costs one extra deploy cycle — the pod
  may crash-loop briefly — whenever the modpack's Minecraft version changes.

Either way, the Minecraft version is resolved to a required Java version via
Mojang's own per-version manifest (the same source the real launcher uses),
so there's no hand-maintained version-range table to keep up to date.

The resolved tag is cached in `.cache/java-tag/<fileId>`, so repeat deploys
of the same pinned pack are instant — delete the entry for a `fileId` to
force re-detection.

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
| `task netpol:install` | Manually widen the network policy (escape hatch — pair with `netpol:steady`) |
| `task netpol:steady` | Manually narrow the network policy back down |
| `task playit:sync-ips` | Fetch playit.gg's published IP ranges (review and commit the diff by hand) |
| `task secrets:encrypt-rotate` | One-time: migrate existing secrets after enabling k3s secrets-encryption on an already-running cluster |

## Secrets encryption at rest

`scripts/setup.sh` configures k3s with `secrets-encryption: true`, so
Kubernetes Secrets (the tunnel's `PLAYIT_SECRET_KEY`, `CF_API_KEY`) are
encrypted in etcd's backing store rather than only base64-encoded.

- **Fresh install:** nothing else to do — every secret is encrypted from the
  start.
- **Already-running k3s that predates this:** re-running `scripts/setup.sh`
  detects the gap, warns it's a cluster-wide restart, and asks to confirm
  before touching it. After it restarts, run `task secrets:encrypt-rotate`
  once — new secrets are encrypted automatically the moment the flag is on,
  but *existing* ones need this explicit migration pass to actually get
  rewritten in their encrypted form.

## Image digest pinning

Both images are pinned by content digest, not just tag — `chart/values.yaml`
requires `playit.image.digest` (its tag is static, so there's no excuse for
it being unset); `image.digest` for the `minecraft` image is resolved fresh
on every `task up`/`upgrade`/`restart` by `scripts/resolve-image-digest.sh`,
since its tag itself is chosen dynamically per-modpack. This means a tag
being silently repointed at different image content (a compromised registry,
a mutated `latest`-style tag) can't change what actually gets deployed.

Bump `playit.image.tag` and re-resolve its digest with:

```bash
./scripts/resolve-image-digest.sh ghcr.io playit-cloud/playit-agent <new-tag>
```

## Troubleshooting

### CoreDNS / metrics-server / local-path-provisioner stuck or crash-looping

Symptom: `kubectl -n kube-system logs coredns-...` shows repeated
`[ERROR] plugin/kubernetes: Failed to watch: ... dial tcp 10.43.0.1:443:
i/o timeout`, CoreDNS never goes `1/1 Ready`, and `metrics-server` /
`local-path-provisioner` crash-loop with the same
`dial tcp 10.43.0.1:443: i/o timeout` against the `kubernetes` Service
(`10.43.0.1` is its ClusterIP).

This is a host firewall problem, not a `CiliumNetworkPolicy` problem — rule
that out first with `kubectl exec -n kube-system <cilium pod> --
cilium-dbg endpoint list`; if every endpoint shows `POLICY ENFORCEMENT:
Disabled`, policy isn't involved.

Root cause: `ufw` (or another host firewall) with a default-deny `INPUT`
policy and no rule for the pod CIDR (`10.0.0.0/24` by default here). Traffic
a pod sends to a Service ClusterIP that resolves to *this node's own IP* —
which is exactly what `kubernetes.default` does, since the API server backs
onto the node itself — gets hairpinned by Cilium onto the host stack
(`hubble observe` shows it as `FORWARDED ... to-stack`, confirming Cilium
isn't the one dropping it) and then silently dropped by the firewall's
`INPUT` chain. Pods in `hostNetwork: true` (there are none in this chart)
wouldn't show the symptom, since same-host traffic goes out `OUTPUT`, which
ufw allows by default — that asymmetry is the tell.

Fix:

```bash
sudo ufw allow from 10.0.0.0/24
```

Then restart whatever was mid-crash when the fix landed — it doesn't
self-heal without a kick:

```bash
kubectl -n kube-system delete pod -l k8s-app=kube-dns
kubectl -n kube-system delete pod -l k8s-app=metrics-server
kubectl -n kube-system delete pod -l app=local-path-provisioner
```

## Excluding a broken mod

Some mods host their file off CurseForge's own CDN, at a URL controlled by the mod's author. If
that host goes defunct, `AUTO_CURSEFORGE`'s per-mod install step fails on that one file and the
whole modpack install is blocked — even though every other mod is fine.

1. Find the mod's CurseForge project slug or numeric ID from its page URL
   (`curseforge.com/minecraft/mc-mods/`**`the-mod-slug`**, or the numeric ID shown further down
   the page).
2. Add it to `modpack.excludeMods` in `chart/values.yaml`:
   ```yaml
   modpack:
     excludeMods: [the-mod-slug]
   ```
3. `task upgrade`.

Whether it's safe to drop a mod server-side is on you to judge — a client-only mod (UI, shaders
helper) is generally safe to exclude, but a mod with real server-side logic may break the pack or
desync from clients still running the full pack. `task upgrade` snapshots the world first, so a
bad exclusion is recoverable the same way a bad `fileId` pin is (see below): `task restore
FILE=...`.

You don't need to touch `modpack.forceSynchronize` yourself — `task upgrade` flips it on for the
deploy and back off once applied.

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

## License

[AGPL-3.0](LICENSE). Provided as-is, with no warranty — see the license for
the full disclaimer. You're responsible for your own deployment, secrets,
and whatever modpack/mods you choose to run.