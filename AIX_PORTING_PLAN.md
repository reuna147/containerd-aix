# AIX Porting Plan: `ctr` CLI

**Branch:** `elladev`  
**Scope:** `cmd/ctr` inside the `containerd-aix` repository only.  
**Target:** Minimum implementation required for `ctr` to build and run on AIX (`GOOS=aix GOARCH=ppc64`).  
**Prerequisite reading:** `PORTING_ANALYSIS.md` — contains the full rationale for every decision below.  
**crictl:** Out of scope. Separate future port.

---

## Constraints

1. **Work only on branch `elladev`.** Do not merge to main.
2. **Ask before any structural change** (adding new packages, moving files between packages, changing public API signatures).
3. **Minimal diff.** Do not refactor upstream code. Follow existing patterns found in `cmd/containerd/command/main_aix.go` and `defaults/defaults_aix.go`.
4. **No implementation code** in this document — this is a plan only.
5. **Every new file must carry** the standard containerd Apache 2.0 license header and an `//go:build aix` tag (or a composite negative tag where appropriate).

---

## Phase 1 — Fix build blockers (required for any `ctr` binary on AIX)

These tasks must be completed before the AIX binary can compile.

### Task 1.1 — Split `cmd/ctr/commands/run/run_unix.go`

**Why:** `run_unix.go` (`//go:build !windows`) is compiled on AIX. It imports
`github.com/intel/goresctrl/pkg/blockio` and
`tags.cncf.io/container-device-interface/pkg/cdi`, which have no AIX support
and will not compile.

**Action:**
1. Change the build tag on the existing `run_unix.go` from `!windows` to
   `linux`.  
   New first line: `//go:build linux`  
   _Ask maintainer before renaming the file — the file name `run_unix.go`
   is conventional; the tag change alone is sufficient without a rename._
2. Create `cmd/ctr/commands/run/run_aix.go` with `//go:build aix`.
3. The new file must define: `NewContainer`, `getNetNSPath`, `platformRunFlags`,
   and all private helpers that `run.go` calls — mirroring the structure of
   `run_unix.go` but with the following omissions:

| Feature removed | Reason |
|----------------|--------|
| `--uidmap` / `--gidmap` / `--remap-labels` flags | No AIX user namespaces |
| `--with-ns` flag and `validNamespace` logic | No AIX kernel namespaces |
| `--privileged-without-host-devices` flag | AIX has no privilege separation model here |
| `--cpus` / `--cpu-shares` / `--cpuset-cpus` / `--cpuset-mems` / `--cpu-quota` / `--cpu-period` / `--cpu-burst` / `--memory-limit` | No cgroup enforcement; can be kept as accepted-but-ignored flags or removed — **ask maintainer** |
| `--seccomp` / `--seccomp-profile` | seccomp unsupported on AIX (stubs exist but kernel enforcement does not) |
| `--apparmor-default-profile` / `--apparmor-profile` | AppArmor unsupported on AIX |
| `--blockio-config-file` / `--blockio-class` | goresctrl not available on AIX |
| `--rdt-class` | RDT (Intel Resource Director Technology) — Linux/x86 only |
| CDI device injection (`--device` with qualified names, `--gpus`) | CDI is Linux-specific |
| `getNetNSPath` (returns `/proc/<pid>/ns/net`) | AIX has no procfs net namespace path |
| `withStaticCDIRegistry`, `withCDIDeviceRequests`, `detectGPUVendor`, `gpuDeviceNames` | CDI helpers — not needed |

**Imports to remove from the AIX file:**
- `github.com/intel/goresctrl/pkg/blockio`
- `tags.cncf.io/container-device-interface/pkg/cdi`
- `tags.cncf.io/container-device-interface/pkg/parser`
- `github.com/containerd/containerd/v2/pkg/cdi`
- `github.com/containerd/containerd/v2/contrib/apparmor`
- `github.com/containerd/containerd/v2/contrib/seccomp`
- `github.com/opencontainers/runtime-spec/specs-go` (re-check; may still be needed for `specs.Mount`)

**Imports to keep:**
- `github.com/containerd/containerd/v2/pkg/oci`
- `github.com/containerd/containerd/v2/client`
- `github.com/containerd/containerd/v2/cmd/ctr/commands`
- `github.com/containerd/containerd/v2/core/containers`
- `github.com/containerd/containerd/v2/core/snapshots`
- `github.com/containerd/containerd/v2/core/diff`
- `github.com/containerd/platforms`
- `github.com/containerd/log`
- `github.com/urfave/cli/v3`
- stdlib: `context`, `errors`, `fmt`, `os`, `path/filepath`, `strings`

**`getNetNSPath` on AIX:**  
Return `"", fmt.Errorf("CNI networking not supported on AIX")` — this prevents `--cni` from silently using a non-existent path.

**`platformRunFlags` on AIX:**  
An empty `[]cli.Flag{}` slice, or a minimal subset without UID/GID maps,
namespaces, CDI, blockio, RDT.

**Note:** The `--rootfs`, `--no-pivot`, `--rootfs-propagation`, `--device`
(non-CDI paths), `--net-host`, `--hostname`, `--rlimit-nofile` flags **can be
kept** in the AIX file because they either use cross-platform OCI spec fields or
are no-ops at runtime.

---

### Task 1.2 — Verify `commands_unix.go` compiles on AIX

**File:** `cmd/ctr/commands/commands_unix.go` (`//go:build !windows`)

The file imports `github.com/containerd/containerd/api/types/runc/options` and
`runtimeoptions/v1`. Both are protobuf-generated; they compile on all platforms.
The runc-specific flags (`--runc-binary`, `--runc-root`, `--runc-systemd-cgroup`)
are harmless — they will be registered but ignored by the AIX WPAR runtime.

**Action:** No file change needed. Verify by attempting an AIX build.

---

### Task 1.3 — Verify `plugins/mount/fsview/erofs` import in `app/main.go`

**File:** `cmd/ctr/app/main.go`, line 49:
```go
_ "github.com/containerd/containerd/v2/plugins/mount/fsview/erofs"
```

`plugins/mount/fsview/erofs/erofs.go` has no OS build tag. Read it to confirm
whether it uses Linux-only mounts or syscalls.

**If it compiles on AIX:** No action needed.  
**If it does not compile on AIX:** Create `cmd/ctr/app/main_linux.go` with
`//go:build linux` that adds the erofs import via `init()` or a side-effect
import, and remove the import from `main.go`.

**Ask the maintainer before restructuring `app/main.go`.**

---

## Phase 2 — Functional improvements (after Phase 1 builds)

These tasks are not required to compile but are needed for a working binary.

### Task 2.1 — `commands_unix.go`: Consider an AIX-specific runtime-options stub

The existing `commands_unix.go` (`//go:build !windows`) provides `RuntimeOptions`
which returns runc-specific options. On AIX the default runtime is
`io.containerd.wpar.v1` (set in `defaults/defaults_aix.go`). The runc path
is silently skipped because the runtime name won't match `io.containerd.runc.v2`.

**Decision:** Keep as-is for now. If runc flags cause confusion, create
`commands_aix.go` (`//go:build aix`) that provides `RuntimeOptions` returning
`nil, nil` always, and guard `commands_unix.go` with `!windows && !aix`.

**Ask maintainer before splitting.**

---

### Task 2.2 — CNI networking stub for AIX

The `run.go` (cross-platform) calls `getNetNSPath` (defined per-platform).
Task 1.1 creates the AIX stub that returns an error. Additionally, `--cni` flag
handling in `run.go` should work correctly — if `--cni` is specified and
`getNetNSPath` returns an error, the user receives a clear message.

No additional file needed beyond Task 1.1.

---

### Task 2.3 — Document unsupported flags

After Task 1.1, the AIX `run` subcommand will have fewer flags than Linux.
Add a comment block at the top of `run_aix.go` explaining which features are
omitted and why.

---

## Phase 3 — Validation

### Task 3.1 — Build check

```sh
GOOS=aix GOARCH=ppc64 go build ./cmd/ctr/...
```

This must succeed with zero compilation errors before any PR is opened.

### Task 3.2 — Lint check

```sh
make check
```

Run against the changed files. If the toolchain is unavailable on the build
machine, report the blocker to the maintainer.

### Task 3.3 — Test check

```sh
GOOS=aix GOARCH=ppc64 go vet ./cmd/ctr/...
```

Unit tests under `cmd/ctr/commands/run/run_unix_test.go` use `//go:build !windows`
and will run on AIX. Confirm they pass or add an `aix` exclusion if a test
exercises Linux-only code.

---

## File Change Summary

| File | Change type | Task |
|------|------------|------|
| `cmd/ctr/commands/run/run_unix.go` | Tag change: `!windows` → `linux` | 1.1 |
| `cmd/ctr/commands/run/run_aix.go` | **New file** | 1.1 |
| `cmd/ctr/app/main.go` | Possible import guard | 1.3 |
| `cmd/ctr/app/main_linux.go` | Possible new file | 1.3 |

All other files under `cmd/ctr` require **no changes**.

---

## Decision Points Requiring Maintainer Sign-Off

Before writing implementation code, confirm the following:

1. **File rename vs tag-only change for `run_unix.go`:**  
   The `AGENTS.md` note says "ask before changing structure." Changing only
   the build tag (not the filename) is preferred for minimal diff. Confirm.

2. **Resource/CPU flags on AIX (`--cpus`, `--memory-limit`, etc.):**  
   Keep them as accepted-but-ignored CLI flags (same UX as Linux), or
   exclude them from the AIX file entirely? Exclusion is cleaner but diverges
   more from upstream.

3. **`--cni` on AIX:**  
   Return an error immediately when `--cni` is specified, or silently skip
   network setup? Returning an error is the safer default.

4. **`commands_unix.go` runc flags on AIX:**  
   Keep the current `!windows` guard (runc flags present but no-op), or split
   to hide runc-specific flags from AIX help output?

5. **erofs fsview import in `app/main.go`:**  
   If the plugin does not compile on AIX, should it be gated with
   `main_linux.go` or with a build tag on the plugin itself?

---

## Out of Scope

- `crictl` — separate future port.
- `cmd/containerd-shim-wpar-v1` — separate; already has AIX-specific code.
- `pkg/shim`, `core/mount`, `pkg/archive`, `plugins/content/local` — already
  ported (AIX files exist).
- Any changes to public protobuf definitions or public Go APIs.
- Changes to `vendor/` — `make vendor` must be run after any `go.mod` changes
  by the maintainer.
