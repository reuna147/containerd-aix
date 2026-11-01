# Porting Analysis: `ctr` CLI for AIX

**Branch:** `elladev`  
**Scope:** `cmd/ctr` and its in-tree dependencies only.  
**Goal:** Identify every Linux-only code path that blocks a successful `GOOS=aix` build.  
**Status:** Analysis only — no implementation code written.

---

## 1. File Inventory with Build-Tag Gaps

The following table lists every platform-conditional file under `cmd/ctr` and
the problem it creates for AIX.

| File | Current guard | Compiles on AIX? | Issue |
|------|---------------|-------------------|-------|
| `cmd/ctr/app/main_unix.go` | `!windows` | ✅ yes | Adds `shim.Command`; shim package itself has `!windows` guard — OK |
| `cmd/ctr/commands/commands_unix.go` | `!windows` | ✅ yes | Pulls in `runc`, cgroup, pivot-root flags; runc flags are harmless on AIX (they won't be wired to a real runtime), but `commands_unix.go` imports `options` proto which exists on all platforms |
| `cmd/ctr/commands/signals.go` | *(no tag)* | ✅ yes | Pure `os/signal` + `syscall` — portable |
| `cmd/ctr/commands/signals_linux.go` | *(no explicit tag = linux only)* | ❌ **no** | Uses `unix.SIGURG`; file has no explicit `//go:build linux` tag so Go infers it from the `_linux` filename suffix — does **not** compile on AIX |
| `cmd/ctr/commands/signals_notlinux.go` | `!linux` | ✅ yes | Covers AIX; `canIgnoreSignal` returns false — correct |
| `cmd/ctr/commands/run/run.go` | *(no tag)* | ✅ yes | Pure cross-platform logic |
| `cmd/ctr/commands/run/run_unix.go` | `!windows` | ❌ **partial** | Heavy Linux deps (see §3 below); compiles on AIX but imports Linux-only packages that have `!linux` unsupported stubs — needs an AIX-specific split |
| `cmd/ctr/commands/run/run_windows.go` | `windows` | n/a | — |
| `cmd/ctr/commands/tasks/tasks_unix.go` | `!windows` | ❌ **partial** | Uses `unix.SIGWINCH` — the constant **exists** on AIX (`zerrors_aix_ppc64.go`, 0x1c), so it compiles. `console.Console` resize is TTY-based and should work. **No blocker.** |
| `cmd/ctr/commands/tasks/tasks_windows.go` | `windows` | n/a | — |
| `cmd/ctr/commands/tasks/metrics.go` | *(no tag)* | ❌ **partial** | Imports `cgroups/v3/cgroup1/stats` and `cgroups/v3/cgroup2/stats` — see §4 |
| `cmd/ctr/commands/shim/io_unix.go` | `!windows` | ✅ yes | Uses `unix.O_WRONLY` etc. which exist on AIX via `zerrors_aix_ppc64.go` |
| `cmd/ctr/commands/shim/shim.go` | `!windows` | ✅ yes | Empty package stub |
| `cmd/ctr/commands/shim/pprof.go` | `!windows` | ✅ yes | Uses `unix.Conn` — present on AIX |
| `cmd/ctr/commands/pprof/pprof_unix.go` | `!windows` | ✅ yes | Pure `net.Dialer` — fully portable |
| `cmd/ctr/commands/namespaces/namespaces_linux.go` | *(no tag = linux)* | n/a (linux suffix) | Not compiled on AIX; `namespaces_other.go` (`!linux`) covers it — ✅ OK |
| `cmd/ctr/commands/namespaces/namespaces_other.go` | `!linux` | ✅ yes | Returns `nil` opts; correct for AIX |
| All other files under `cmd/ctr/commands/` | *(no tag)* | ✅ yes | Cross-platform |

---

## 2. Feature-by-Feature Analysis

### 2.1 seccomp

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 285–296; flags `--seccomp`, `--seccomp-profile` |
| **Import** | `github.com/containerd/containerd/v2/contrib/seccomp` |
| **AIX situation** | `contrib/seccomp/seccomp_default.go` has `//go:build linux`; the stub `seccomp_default_unsupported.go` has `//go:build !linux` and provides `WithDefaultProfile` / `WithProfile` as no-ops. **The package already compiles on AIX with no-op stubs.** |
| **Decision** | **Stub** — the import compiles correctly; no special AIX file needed. The flags will be accepted by the CLI but silently ignored by the no-op stubs. A runtime error should be produced if the user explicitly passes `--seccomp` (because there is no kernel enforcement). |
| **Action needed** | None at the package level. The AIX `run` file should document that seccomp is unsupported. |

### 2.2 AppArmor

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 299–307; flags `--apparmor-default-profile`, `--apparmor-profile` |
| **Import** | `github.com/containerd/containerd/v2/contrib/apparmor` |
| **AIX situation** | `contrib/apparmor/apparmor.go` has `//go:build linux`; `apparmor_unsupported.go` has `//go:build !linux` and provides all exported functions as no-ops. **Compiles on AIX.** |
| **Decision** | **Stub** — same pattern as seccomp. Flags accepted; silently ignored. |
| **Action needed** | None at the package level. |

### 2.3 Cgroups (metrics display + run flags)

| Item | Detail |
|------|--------|
| **Where used** | `tasks/metrics.go` lines 28–29 imports `cgroups/v3/cgroup1/stats` and `cgroups/v3/cgroup2/stats`. Also `run_unix.go` references `oci.WithCgroup`, `oci.WithCPUCFS`, `oci.WithMemoryLimit`, etc. |
| **cgroups stats package** | These are protobuf-generated stat structs. They have **no OS build constraint** and compile on any platform (they are pure data types). ✅ |
| **oci.WithCgroup etc.** | Defined in `pkg/oci/spec_opts.go` (no build tag) — they manipulate the OCI spec struct in-memory. They compile on AIX but are irrelevant at runtime since AIX uses WPARs, not cgroups. ✅ |
| **run flags** | `--cgroup`, `--cpu-quota`, `--cpu-period`, `--cpu-shares`, `--cpus`, `--cpuset-cpus`, `--cpuset-mems`, `--memory-limit`, `--cpu-burst`, `--blockio-*`, `--rdt-class` all originate from `run_unix.go` (guard `!windows`). They will compile on AIX. |
| **Decision** | **Supported at compile time; ignored at runtime** — the WPAR runtime will not honour cgroup-style resource constraints unless the AIX WPAR shim implements them. |
| **Action needed** | The AIX `run` file can omit these flags entirely, or keep them and document they are no-ops. Keeping them is cleaner for now (less divergence from upstream). |

### 2.4 SIGWINCH (TTY resize)

| Item | Detail |
|------|--------|
| **Where used** | `tasks/tasks_unix.go` line 54: `signal.Notify(s, unix.SIGWINCH)` |
| **AIX situation** | `unix.SIGWINCH` is defined in `vendor/golang.org/x/sys/unix/zerrors_aix_ppc64.go` (value 0x1c). **Fully supported on AIX.** |
| **Decision** | **Supported** — no change needed. |
| **Action needed** | None. |

### 2.5 CDI (Container Device Interface)

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 41, 44, 47 — imports `pkg/cdi`, `intel/goresctrl/pkg/blockio`, `tags.cncf.io/container-device-interface/pkg/cdi` |
| **CDI vendor package** | `tags.cncf.io/container-device-interface` — no AIX-specific files; uses `os.ReadDir`, JSON, no syscalls. Likely compiles on AIX. **Needs verification at build time.** |
| **goresctrl/blockio** | Uses `/sys/fs/resctrl` and Linux-specific `mknod` syscalls. `vendor/github.com/intel/goresctrl` has no AIX support. **Will not compile on AIX.** |
| **pkg/cdi (in-tree)** | `pkg/cdi/cdi.go` — no build tag; wraps the external CDI library. Likely compiles if the external library does. **Needs verification.** |
| **Decision** | **Disable on AIX** — CDI and RDT/blockio are inherently Linux concepts. The `run_unix.go` file must be split: a `run_linux.go` with CDI + blockio + RDT, and a `run_aix.go` (or `run_notlinux_notwindows.go`) that omits them. |
| **Action needed** | Split `run_unix.go`. Create AIX variant without CDI, blockio, RDT. |

### 2.6 Linux Namespaces (`--with-ns`)

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 343–356; flag `--with-ns` accepting `nstype:path` |
| **Import** | `oci.WithLinuxNamespace` in `pkg/oci/spec_opts.go` (no build tag) |
| **AIX situation** | Linux namespace types (`pid`, `net`, `mnt`, `uts`, `ipc`, `user`, `cgroup`) are Linux kernel concepts. AIX has WPARs instead. The OCI spec `s.Linux.Namespaces` field exists cross-platform (it's a struct field), so it compiles. |
| **Decision** | **Disable on AIX** — `--with-ns` flag and its logic should be excluded from the AIX `run` file. The WPAR shim does not support namespace joining. |
| **Action needed** | Omit `--with-ns` handling in the AIX `run` stub. |

### 2.7 Privileged containers / host devices

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 234–245; flags `--privileged`, `--privileged-without-host-devices` |
| **Imports** | `oci.WithPrivileged`, `oci.WithAllDevicesAllowed`, `oci.WithHostDevices` |
| **`oci.WithHostDevices`** | Defined in `pkg/oci/spec_opts_unix.go` (`!linux && !windows`) — available for AIX. It calls `HostDevices()` which reads `/dev`. Should compile. |
| **Decision** | **Supported** — no special AIX action needed. Runtime behaviour depends on the WPAR shim. |

### 2.8 User namespace ID mappings (`--uidmap`, `--gidmap`)

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 51–58 (flags), 189–215 (logic) |
| **AIX situation** | AIX has no user namespaces. The OCI spec types (`specs.LinuxIDMapping`) are cross-platform structs. The compile will succeed but the WPAR runtime won't support it. |
| **Decision** | **Stub / disable on AIX** — omit from AIX run file. |

### 2.9 OCI spec generation for the container

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` calls `oci.WithDefaultSpecForPlatform(platform)` |
| **`pkg/oci/spec_nonlinux.go`** | `//go:build !linux` — provides `WithDefaultSpec` / `WithDefaultSpecForPlatform` for non-linux. Compiles on AIX. ✅ |
| **`pkg/oci/spec_opts_nonlinux.go`** | `//go:build !linux` — provides `WithAllCurrentCapabilities`, `WithAllKnownCapabilities` as no-ops. ✅ |
| **Decision** | **Supported.** |

### 2.10 `contrib/seccomp` and `contrib/apparmor` import in `run_unix.go`

Both packages already provide `!linux` unsupported stubs. Because `run_unix.go`
uses the `!windows` guard, it is compiled on AIX. The imports will resolve to
the unsupported stubs and compile cleanly. However, the **full body of
`run_unix.go`** also references `blockio` and CDI packages that likely do **not**
compile on AIX (see §2.5). Therefore the file must be split regardless.

### 2.11 `goresctrl/blockio` (RDT/blockio)

| Item | Detail |
|------|--------|
| **Where used** | `run_unix.go` lines 44, 397–409 |
| **Vendor path** | `vendor/github.com/intel/goresctrl/pkg/blockio` |
| **AIX situation** | Uses `/sys/fs/resctrl`, Linux-only ioctl, and `mknod`. No AIX support in vendor. **Will not compile.** |
| **Decision** | **Disable on AIX** — must be excluded from the AIX `run` file. |

### 2.12 procfs usage

| Item | Detail |
|------|--------|
| **Where used in `cmd/ctr`** | `run_unix.go` line 514: `fmt.Sprintf("/proc/%d/ns/net", task.Pid())` for CNI net NS path |
| **AIX situation** | AIX does not have `/proc/<pid>/ns/net`. If CNI networking is requested on AIX via `--cni`, `getNetNSPath` will return a path that does not exist. |
| **Decision** | **Stub on AIX** — `getNetNSPath` should return an error or unsupported error on AIX. The AIX `run` file should not include CNI networking. |

---

## 3. Deep Dive: `run_unix.go` Compilation Blockers

`run_unix.go` has `//go:build !windows` — it compiles on AIX today. However,
it transitively imports packages that do not compile on AIX:

| Package | Reason |
|---------|--------|
| `github.com/intel/goresctrl/pkg/blockio` | Reads Linux `/sys/fs/resctrl`; uses Linux-only constants |
| `tags.cncf.io/container-device-interface/pkg/cdi` | Likely compiles but needs verification; conceptually Linux-only |
| `github.com/containerd/containerd/v2/pkg/cdi` | Depends on external CDI library above |

**The file must be split.** The minimal split strategy is:

1. Rename `run_unix.go` → `run_linux.go` (add `//go:build linux`) for full Linux feature set.
2. Create `run_aix.go` (`//go:build aix`) with the subset of `NewContainer` logic
   that is valid on AIX, omitting: CDI, blockio, RDT, `--with-ns`, `--uidmap`/`--gidmap`, procfs net NS.
3. Optionally create `run_other_unix.go` (`//go:build !linux && !windows && !aix`)
   for FreeBSD/other if needed (may already be covered by existing guards).

---

## 4. Findings Summary Table

| Feature | AIX-compatible? | Strategy | New file needed? |
|---------|-----------------|----------|-----------------|
| seccomp | Stubs present | Stub (no-op) | No |
| AppArmor | Stubs present | Stub (no-op) | No |
| cgroups stats types | Pure proto types | Supported | No |
| cgroup flags / oci opts | In-memory only | Keep, no-op at runtime | No |
| SIGWINCH | In AIX `unix` pkg | Supported | No |
| SIGURG (signals_linux.go) | In AIX `unix` pkg | n/a — already guarded by `_linux` suffix | No |
| CDI (external) | Unknown | Disable | Yes (`run_aix.go`) |
| goresctrl/blockio | No AIX support | Disable | Yes (`run_aix.go`) |
| RDT (`--rdt-class`) | No AIX support | Disable | Yes (`run_aix.go`) |
| Linux namespaces | No kernel support | Disable | Yes (`run_aix.go`) |
| UID/GID mappings | No kernel support | Disable | Yes (`run_aix.go`) |
| procfs net NS path | No `/proc/<pid>/ns` | Stub (return error) | Yes (`run_aix.go`) |
| Privileged / host devices | Can compile | Keep | Yes (`run_aix.go`) |
| TTY / console resize | SIGWINCH works | Supported | No |
| pprof unix socket | Pure net.Dialer | Supported | No |
| shim FIFO I/O | unix.O_* exist | Supported | No |

---

## 5. Files That Need No Changes

The following files under `cmd/ctr` require **zero** changes for AIX:

- `commands/commands.go` — pure flag definitions, no OS calls
- `commands/client.go` — pure gRPC, no OS calls
- `commands/signals.go` — `os/signal` + `syscall`, portable
- `commands/signals_notlinux.go` — already covers AIX via `!linux`
- `commands/resolver.go`
- `commands/cni.go`
- `commands/tasks/tasks.go`, `attach.go`, `checkpoint.go`, `delete.go`,
  `exec.go`, `exec_test.go`, `kill.go`, `list.go`, `pause.go`, `ps.go`,
  `resume.go`, `start.go`
- `commands/tasks/tasks_unix.go` — `unix.SIGWINCH` exists on AIX
- `commands/tasks/metrics.go` — cgroups stat types are cross-platform structs
- `commands/containers/containers.go`, `containers_test.go`, `restore.go`
- `commands/containers/checkpoint.go`
- All of `commands/content/`, `commands/events/`, `commands/images/`,
  `commands/info/`, `commands/install/`, `commands/leases/`,
  `commands/namespaces/` (other file covers AIX), `commands/oci/`,
  `commands/plugins/`, `commands/pprof/`, `commands/sandboxes/`,
  `commands/snapshots/`, `commands/version/`, `commands/deprecations/`
- `app/main.go` — all imports resolve on AIX
- `app/main_unix.go` — includes shim command; shim FIFO I/O works on AIX
- `main.go`

---

## 6. Notes on `tasks/metrics.go`

`metrics.go` imports `cgroups/v3/cgroup1/stats` and `cgroups/v3/cgroup2/stats`.
These are **protobuf-generated Go types** (pure structs, no syscalls). They have
no OS build constraint and compile on any platform. The `metrics` command will
compile and run on AIX; it will return an error at runtime if the server returns
an unrecognised metric type, which is expected.

---

## 7. Erofs / fsview plugin import in `app/main.go`

```go
_ "github.com/containerd/containerd/v2/plugins/mount/fsview/erofs"
```

`plugins/mount/fsview/erofs/erofs.go` has no OS build tag. It must be inspected
to confirm it compiles on AIX. If it uses Linux-only mounts, this import may
also need a platform guard in `app/main.go` (via a new `app/main_linux.go` that
adds it for Linux only, and removing it from `main.go`).
