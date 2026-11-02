# UniversalRun

> **Run the apps you already have.**
> UniversalRun is a desktop orchestration and compatibility-management platform for running Windows desktop applications on Linux without manual Wine prefix configuration, DLL overrides, or ambient host access.

---

## Architecture Overview

```
UI Process (Tauri / React)
     │  Local IPC (Unix Domain Socket)
Supervisor Daemon (Rust, unprivileged)
     │  Spawns and monitors
Runtime Process (Runtime Controller + Sandbox Launcher)
     │
Application Process (Wine + Windows App inside Bubblewrap Sandbox)
```

## Repository Structure

```
universalrun/
  apps/
    desktop-ui/          # Tauri + React (Milestone 5)
  crates/
    analyzer/            # PE headers, subsystem, dependencies, installer detection
    profile-manager/     # Isolated per-app profiles & manifest generation
    recipe-engine/       # Signed declarative recipes & dependency resolver
    runtime-wine/        # Wine/Proton runtime management
    sandbox/             # Bubblewrap launcher, Landlock/seccomp integration
    supervisor/          # Daemon, process monitoring, IPC
    diagnostics/         # Error classifier, log sanitization, diagnostic bundle
    common/              # Shared types, traits, IPC protocols
  recipes/               # Sample signed recipes & JSON Schema
  docs/                  # ADRs, research, threat models
  tests/                 # Fixtures & integration test harnesses
```

---

## Milestone 0 (Feasibility Spike)

Milestone 0 proves that running Windows GUI binaries in Wine inside an unprivileged Bubblewrap sandbox with zero host `$HOME` access is viable and sound.

### Running the Spike (on Linux x86_64)

```bash
# Ensure dependencies are present: bwrap, wine, wineserver, xauth, curl, unzip
chmod +x tests/fixtures/*.sh
./tests/fixtures/m0_spike.sh
```

### Key Milestone 0 Documents
- [ADR 0001: Wine in Bubblewrap Feasibility (Go/No-Go)](docs/adr/0001-wine-in-bubblewrap-feasibility.md)
- [Research: Ubuntu 24.04 AppArmor & Unprivileged User Namespaces](docs/research/ubuntu-24-04-userns-apparmor.md)
- [Research: Display Isolation (X11 vs Wayland vs Nested Servers)](docs/research/display-isolation-x11-wayland.md)
