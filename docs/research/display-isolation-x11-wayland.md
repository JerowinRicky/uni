# Research: Display Isolation in Linux (X11 vs Wayland vs Nested Servers)

## 1. The Security Dilemma of Linux Display Protocols

Wine Windows applications are GUI-centric. To display windows, Wine must communicate with a host display server. However, the display server channel can undermine filesystem and network sandboxing if not carefully isolated.

### The X11 Risk (Root Hole for Sandboxing)
Under standard X11 (Xorg or rootless XWayland):
- Any client connected to the display socket (`/tmp/.X11-unix/X0`) can inspect all window titles, observe window hierarchies, grab input focus, log keystrokes from other applications (keylogging), and capture screenshot bitmaps of the entire desktop.
- Mounting `/tmp/.X11-unix/X0` directly into a Bubblewrap container allows untrusted Windows code to compromise the host user's desktop security.

### Scoped Xauthority
In M0, we implemented scoped Xauthority generation:
```bash
xauth -f /tmp/.scoped_xauth add :0 . <host_cookie>
```
**Finding**: Scoped Xauthority controls *authentication* (who can connect to the X server), but once connected, the X11 protocol does *not* restrict intra-client surveillance. Scoped cookies do not prevent an untrusted app from capturing keystrokes meant for other windows.

---

## 2. Wayland Native Isolation

Wayland was designed specifically to prevent client-to-client snooping:
- Clients cannot see or manipulate windows belonging to other clients.
- Keystrokes are strictly dispatched to the currently focused window.
- Screen capture requires compositor-mediated desktop portal consent (`xdg-desktop-portal`).

### Wine 9.0+ Wayland Driver
Starting with Wine 9.0, experimental native Wayland support is included.
When enabled:
- Wine renders directly into Wayland surfaces using `$WAYLAND_DISPLAY` and `$XDG_RUNTIME_DIR`.
- No X11 socket is needed.
- Full display isolation is maintained without auxiliary software.

**Limitation**: Some legacy Win32 apps (custom window decorations, old multi-window dialogs) exhibit quirks under the Wine Wayland driver.

---

## 3. Nested Display Servers for Real Isolation

For apps requiring X11 (or running on X11 hosts), running a **nested display server** per sandbox is the only mechanism that provides true isolation.

### Option A: Nested Xwayland (On Wayland Hosts)
On Wayland hosts, UniversalRun can launch a dedicated rootless Xwayland process per application sandbox:
```bash
Xwayland :100 -rootless -displayfd 3
```
- The nested Xwayland connects to host Wayland as an ordinary Wayland client.
- The sandboxed Wine app only sees `:100`.
- The app can only see and interact with its own X11 windows; it cannot see the host browser, terminal, or other apps.

### Option B: Gamescope (Nested Micro-compositor)
- Originally developed by Valve for SteamOS/Proton.
- Runs an isolated Wayland compositor internally while presenting a single managed window to the host.
- Perfect isolation, but carries dependencies on Vulkan and DRM/KMS support. Overkill for lightweight Win32 business software.

### Option C: Xpra / Sommelier
- Xpra allows seamless application forwarding across an isolated X11 bridge.
- Sommelier (developed for ChromeOS Crostini) bridges X11 and Wayland with seamless window management and isolated IPC.

---

## 4. Architecture Recommendation for UniversalRun

1. **Host on Wayland + Native Wine Wayland**:
   - Best performance and zero external dependencies. Use Wine's native Wayland driver when compatible.
2. **Host on Wayland + Win32 X11 dependency**:
   - Launch a dedicated nested `Xwayland` server per app sandbox. This isolates X11 traffic completely from other applications.
3. **Host on pure Xorg (legacy)**:
   - Provide clear security disclaimer: "Running on native X11 cannot prevent window surveillance. Wayland host recommended for full sandbox guarantees."

