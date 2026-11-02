# ADR 0001: Wine Execution inside Bubblewrap Sandbox (Feasibility & Go/No-Go)

## Status
**ACCEPTED (GO)**

## Context
UniversalRun's core value proposition requires running untrusted Windows applications on Linux with real sandboxing, zero manual prefix management, and no ambient access to the host `$HOME` directory.

Because Wine is explicitly not a security boundary, running Wine directly against the host filesystem allows any Windows binary to access, modify, or exfiltrate user files in `$HOME` (and across any accessible mounts via Wine's automatic `Z:\` root mapping).

Milestone 0 investigated whether running Wine and `wineserver` inside an unprivileged Bubblewrap (`bwrap`) container is technically viable without sacrificing stability, graphic performance, or process management.

---

## Findings from M0 Spike

### 1. Prefix Initialization (`wineboot`) Must Run Inside the Sandbox
- If `wineboot` is run outside the sandbox, Wine inspects the host `/`, scans all mounted disks, auto-creates `dosdevices/z: -> /`, and links user shell folders (`Desktop`, `Documents`, `Downloads`) directly to host `/home/<user>/*`.
- **Decision**: Prefix creation must execute *inside* an isolated Bubblewrap setup container (`wineboot -u`) with `$HOME` set to a throwaway `/tmp` directory.

### 2. Prefix Sanitization is Mandatory
Even when initialized inside a sandbox:
- Wine creates `dosdevices/z:` pointing to `/`.
- Wine sets registry entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` pointing to external paths.
- **Decision**: Before any application is launched, UniversalRun's filesystem adapter must execute a sanitization pass:
  1. Remove `dosdevices/z:`.
  2. Rewrite Explorer Shell Folder registry keys to stay within `%USERPROFILE%` (`C:\users\<user>\...`).
  3. Ensure no symlinks inside `drive_c/users/` point outside the prefix.
- **Verification**: In the File -> Open dialog of Notepad++, the host filesystem is completely absent. The file explorer view is strictly constrained to `C:` and the mapped app directory.

### 3. Bubblewrap Mount Ordering & IPC Rules
- **Rule**: `--tmpfs /tmp` MUST precede any bind mounts located under `/tmp` (such as the scoped X11 socket `/tmp/.X11-unix/X0`). Reversing this order hides the X11 socket.
- **Device nodes**: `--dev /dev` and `--proc /proc` are mandatory. Wine relies on `/dev/null`, `/dev/urandom`, and process information in `/proc` for thread and synchronization handles.
- **Hardware Acceleration**: `--dev-bind /dev/dri /dev/dri` and `--ro-bind /usr/share/vulkan` are required for hardware graphics acceleration (Vulkan, DXVK, OpenGL).

### 4. Wineserver Lifecycle Management
- Running with `--unshare-all` (specifically PID and IPC namespaces) ensures that all Wine processes and `wineserver` belong to the container's PID namespace.
- Terminating the root container process cleanly tears down `wineserver` without leaving orphan host processes.

---

## Verdict: GO

Running Wine inside Bubblewrap is **viable and sound** for the UniversalRun architecture. It provides true filesystem isolation, eliminates ambient host `$HOME` access, and preserves application functionality.

---

## Top 3 Remaining Technical Risks

1. **Host Unprivileged User Namespace Restrictions (Ubuntu 24.04 AppArmor)**:
   - Modern Linux distributions (Ubuntu 24.04+) restrict `CLONE_NEWUSER` by default via AppArmor.
   - *Mitigation*: Distribute an AppArmor profile in the official `.deb` package; provide pre-flight diagnostics and configuration instructions for unpackaged/AppImage runs.
2. **Display Server Isolation on Legacy X11**:
   - Passing `/tmp/.X11-unix/X0` allows untrusted clients to snoop on other X11 windows regardless of filesystem sandboxing.
   - *Mitigation*: Recommend Wayland hosts with native wine-wayland; provide a nested Xwayland micro-server profile for untrusted apps requiring X11.
3. **Complex Installer Process Orchestration**:
   - Multi-stage installers (NSIS/Inno/MSI) fork detached helper processes into the background and exit the main installer stub early.
   - *Mitigation*: UniversalRun supervisor must track process trees via Linux PID namespaces / cgroups rather than relying solely on the exit code of the initial launched binary.
