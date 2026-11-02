# ADR 0001: Wine Execution inside Bubblewrap Sandbox (Feasibility & Go/No-Go)

## Status
**PROVISIONAL (Awaiting verification on real Linux host)**

---

## Context
UniversalRun's core value proposition requires running untrusted Windows applications on Linux with real sandboxing, zero manual prefix management, and no ambient access to the host `$HOME` directory.

Because Wine is explicitly not a security boundary, running Wine directly against the host filesystem allows any Windows binary to access, modify, or exfiltrate user files in `$HOME` (and across any accessible mounts via Wine's automatic `Z:\` root mapping).

Milestone 0 investigates whether running Wine and `wineserver` inside an unprivileged Bubblewrap (`bwrap`) container is technically viable without sacrificing stability, graphic performance, or process management.

---

## Claims and Evidence Status

### 1. Workspace Scaffolding and Trait Architecture
- **Claim**: The Rust workspace builds and defines clean adapter traits (`PlatformAdapter`, `RuntimeBackend`, `SandboxBackend`, etc.) with zero compilation errors.
- **Evidence**: `[Observed]`
  - Command: `cargo check`
  - Output: `Finished dev profile [unoptimized + debuginfo] target(s) in 2m 11s` (Exit code: 0)

### 2. Prefix Bootstrap Inside Sandbox (`wineboot -u`)
- **Claim**: Running `wineboot -u` inside a Bubblewrap container with a throwaway `/tmp` as `$HOME` prevents Wine from embedding host home paths into default registry configs during initial setup.
- **Evidence**: `[Untested / Expected]` (Requires validation on Linux host running `tests/fixtures/m0_spike.sh`).

### 3. Prefix Sanitization (Z: Drive & Shell Folders)
- **Claim**: Removing `dosdevices/z:` and replacing shell-folder symlinks (`Desktop`, `Documents`, `Downloads`) with real prefix directories isolates the Windows application from the host root and host `$HOME`.
- **Evidence**: `[Untested / Expected]` (Requires validation on Linux host running `tests/fixtures/sanitize_prefix.sh` and inspecting `dosdevices/` and file picker behavior).

### 4. Bubblewrap Mount Ordering & IPC
- **Claim**: Mounting `--tmpfs /tmp` before bind-mounting the X11 socket `/tmp/.X11-unix/X0` prevents masking the display socket.
- **Evidence**: `[Untested / Expected]` (Standard Bubblewrap behavior, requires confirmation during live GUI launch).

### 5. Wineserver Lifecycle and Host Process Teardown
- **Claim**: Running with `--unshare-all` (specifically PID and IPC namespaces) ensures `wineserver` and all child processes are killed when the container exits, leaving zero orphan processes on the host.
- **Evidence**: `[Untested / Expected]` (Must be verified using `pgrep -a wineserver` and `pgrep -a wine` after sandbox exit).

### 6. Exit Code and Crash Propagation
- **Claim**: Process failure or crash inside the sandbox propagates its exit code back through Bubblewrap to the supervisor caller.
- **Evidence**: `[Untested / Expected]` (Must be verified with a deliberate non-zero exit / crash test).

### 7. Ubuntu 24.04 AppArmor User Namespace Restrictions
- **Claim**: Stock Ubuntu 24.04 blocks unprivileged `bwrap` execution via `kernel.apparmor_restrict_unprivileged_userns=1`, requiring either an AppArmor profile or a sysctl override.
- **Evidence**: `[Untested / Expected]` (Must be verified by running `bwrap --unshare-user --true` before and after the sysctl/AppArmor toggle).

---

## Verdict: PROVISIONAL

The architecture and harness scripts are ready, but the feasibility verdict remains **PROVISIONAL** until the spike script is executed on a live Linux x86_64 host (Ubuntu 24.04) and produces the required evidence log.

### Criteria to Flip Verdict to "ACCEPTED (GO)":
1. Notepad++ GUI launches under `bwrap` on Ubuntu 24.04 with no ambient `$HOME` mounted.
2. Verified absence of `dosdevices/z:` and zero symlinks pointing to host paths.
3. Zero orphan `wineserver` or `wine` processes detected via `pgrep` after sandbox exit.
4. Clean propagation of non-zero exit codes during crash tests.
5. Documented behavior with and without Ubuntu 24.04 AppArmor userns restrictions.

---

## Top 3 Technical Risks (Pending Verification)

1. **Host Unprivileged User Namespace Restrictions (Ubuntu 24.04 AppArmor)**:
   - Modern Linux distributions restrict `CLONE_NEWUSER` by default via AppArmor.
   - *Mitigation to test*: Distribute an AppArmor profile in `.deb` package; provide pre-flight diagnostics for unpackaged/AppImage runs.
2. **Display Server Isolation on Legacy X11**:
   - Passing `/tmp/.X11-unix/X0` allows untrusted clients to snoop on other X11 windows regardless of filesystem sandboxing.
   - *Mitigation to test*: Wayland hosts with native wine-wayland or nested Xwayland micro-server.
3. **Detached Child Installer Processes & Wineserver Persistence**:
   - Installers or misbehaving apps spawning detached background helpers that prevent `wineserver` from exiting cleanly.
   - *Mitigation to test*: Verify process tree termination via container PID namespace boundaries.
