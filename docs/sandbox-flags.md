# UniversalRun Sandbox Bubblewrap Flags & Security Boundary Specification

> **Verification Status**:
> - Argument generation logic, ordering, safety checker, and path rejection: **Unit-tested on Windows (Observed)**
> - Linux bubblewrap kernel execution (`bwrap`), namespaces, and mount isolation: **UNTESTED ON LINUX**

---

## 1. Flag Architecture and Vector Construction

Bubblewrap arguments are synthesized strictly as typed `Vec<OsString>` data structures, never concatenated as shell strings. The construction follows strict phase ordering.

| Flag / Argument | Purpose & Invariant | Status |
| :--- | :--- | :--- |
| `--unshare-all` | Unshares user, mount, pid, ipc, and net namespaces. Enforces zero initial host resource sharing. | Unit-tested (UNTESTED ON LINUX) |
| `--unshare-uts` | Creates an isolated UTS namespace for custom hostname isolation. | Unit-tested (UNTESTED ON LINUX) |
| `--hostname universalrun-sandbox` | Replaces the host system hostname with a sanitized static container hostname. | Unit-tested (UNTESTED ON LINUX) |
| `--share-net` | Re-enables networking when explicitly allowed in the `SandboxPolicy`. **Must always appear after `--unshare-all`**. | Unit-tested (UNTESTED ON LINUX) |
| `--die-with-parent` | Ensures the sandbox process and sub-tree automatically terminate if UniversalRun exits or crashes. | Unit-tested (UNTESTED ON LINUX) |
| `--new-session` | Creates a new session (`setsid()`), disconnecting controlling terminal. | Unit-tested (UNTESTED ON LINUX) |
| `--cap-drop ALL` | Drops all Linux capabilities (including `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`). | Unit-tested (UNTESTED ON LINUX) |
| `--clearenv` | Wipes the entire host environment block, preventing leakage of host API keys, tokens, or paths. | Unit-tested (UNTESTED ON LINUX) |
| `--setenv <KEY> <VAL>` | Reconstructs an explicit, minimal allowlist of environment variables: `HOME=/wineprefix`, `WINEPREFIX=/wineprefix`, `WINEARCH`, `LANG`, `PATH`, `WINESERVER`, `WINEDEBUG`, `WINEDLLOVERRIDES`, plus `DISPLAY`/`XAUTHORITY` or `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR`. | Unit-tested (UNTESTED ON LINUX) |
| `--proc /proc` | Mounts a fresh, unshared `/proc` pseudo-filesystem revealing only processes inside the sandbox PID namespace. | Unit-tested (UNTESTED ON LINUX) |
| `--dev /dev` | Mounts a minimal, isolated `/dev` tmpfs populated with safe standard nodes (`null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx`). Host `/dev` is NEVER bound. | Unit-tested (UNTESTED ON LINUX) |
| `--tmpfs /tmp` | Mounts a clean `tmpfs` at `/tmp`. **Must be declared BEFORE mounting any X11 or audio sockets under `/tmp`**. | Unit-tested (UNTESTED ON LINUX) |
| `--ro-bind-try /usr`, `/lib`, `/lib64`, `/bin`, `/sbin` | Read-only mounts of host binary runtimes, conforming to usr-merged Linux distributions. | Unit-tested (UNTESTED ON LINUX) |
| Specific `/etc` binds (`ld.so.cache`, `fonts`, `machine-id`, `resolv.conf`) | Binds narrow, specific files only. **Never mounts all of `/etc`** to prevent exposing sensitive files like `/etc/shadow` or `/etc/sudoers`. | Unit-tested (UNTESTED ON LINUX) |
| Specific `/etc/ssl`, `/etc/pki`, `/etc/ca-certificates` | Read-only binds for root certificates, mounted **only when network access is enabled**. | Unit-tested (UNTESTED ON LINUX) |
| `--ro-bind <runtime> /usr/lib/wine` | Pinned Wine runtime mount, strictly read-only. | Unit-tested (UNTESTED ON LINUX) |
| `--bind <prefix> /wineprefix` | The application Wine prefix. **This is the ONLY writable application directory inside the container**. | Unit-tested (UNTESTED ON LINUX) |
| `--dev-bind-try /dev/dri` | Direct Rendering Infrastructure device nodes, bound **only when GPU access is granted**. | Unit-tested (UNTESTED ON LINUX) |
| `--ro-bind-try /sys/dev/char`, `/sys/devices` | Narrow sysfs paths required by Vulkan/OpenGL user-space drivers (Mesa, NVIDIA), bound **only when GPU access is granted**. | Unit-tested (UNTESTED ON LINUX) |
| Scoped X11 / Wayland binds | Binds only `/tmp/.X11-unix/X0` and cookie (for X11) or specific `/run/user/1000/wayland-0` socket. | Unit-tested (UNTESTED ON LINUX) |
| Scoped Pulse/PipeWire socket | Binds `/run/user/1000/pulse/native` or equivalent, **only when audio is granted**. | Unit-tested (UNTESTED ON LINUX) |
| Explicit `--ro-bind` / `--bind` for granted folders | Mounts user-authorized folders at explicit container paths; validates each path against forbidden roots and sensitive credentials. | Unit-tested (UNTESTED ON LINUX) |
| `--` | Bubblewrap argument terminator; prevents application command and arguments from being parsed as bwrap options. | Unit-tested (UNTESTED ON LINUX) |

---

## 2. Security Boundaries & Honest Capabilities

### 2.1 Wine is Not a Security Boundary
Wine translates Windows NT system calls into POSIX user-space calls. Any Windows process running inside Wine executes with user-space POSIX privileges. Wine does not restrict filesystem, network, or hardware access. **Bubblewrap is the sole isolation boundary**.

### 2.2 Audio vs. Microphone Enforcement Limitation
- When `audio = false`: Audio and microphone access is fully blocked (`enforcement: yes`), as all sound daemon sockets are omitted.
- When `audio = true` and `microphone = false`: **Enforcement status is `NO`**.
  - **Reason**: The standard PulseAudio and PipeWire UNIX domain sockets do not implement client-side permission separation between playback and capture without desktop portals (e.g., `xdg-desktop-portal`) or custom daemon-side policy filters.
  - Bubblewrap cannot inspect or filter UNIX socket stream traffic.
  - UniversalRun's policy model honestly reports `microphone = (EnforcementLevel::No, "CANNOT BE ENFORCED: Exposing audio socket permits microphone recording without daemon portal filtering")`.

### 2.3 Display Server Isolation Trade-off
- **X11 (`enforcement: partial`)**: The X11 protocol does not isolate clients. Any client connected to `:0` can snoop keystrokes from other windows, capture entire desktop framebuffers, and inject synthetic input events. Mitigated only by scoped Xauthority and eventual Xwayland rootful nesting.
- **Wayland (`enforcement: yes`)**: The Wayland protocol natively isolates clients; windows cannot see other windows' framebuffers or keystrokes without explicit compositor-mediated protocols.

### 2.4 GPU Attack Surface (`enforcement: partial`)
- Exposing `/dev/dri/card0` and `/dev/dri/renderD128` passes direct ioctls to the host GPU kernel drivers. Flaws or privilege escalations in host kernel DRM/DRI drivers are directly reachable from inside the sandbox.

### 2.5 Deferred Hardening
- **Seccomp Filters**: System-call filtering via BPF (`--seccomp <fd>`) is deferred until host Linux testing, as Wine and Vulkan drivers require extensive sets of syscalls (e.g. `clone`, `prctl`, `mmap`, `futex`).
- **Landlock LSM**: In-kernel path restrictions via Landlock are deferred until host Linux kernel verification.

### 2.6 Known First-Run Linux Risks
- **X11 Abstract Sockets**: Under `--unshare-all`, bubblewrap creates a new network namespace. In X11, abstract sockets (`@/tmp/.X11-unix/X0`) live in the network namespace and become unreachable once the network namespace is unshared. Testing on Linux must verify whether the host X server listens on filesystem sockets (`/tmp/.X11-unix/X0`) or abstract sockets.
- **systemd-resolved symlink**: `/etc/resolv.conf` on modern systemd distributions is often a symlink to `/run/systemd/resolve/stub-resolv.conf`. Binding only `/etc/resolv.conf` without `/run/systemd/resolve` can result in a dangling symlink.
