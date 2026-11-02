# Research: Ubuntu 24.04 Unprivileged User Namespaces & AppArmor Restrictions

## 1. Background

Starting with Ubuntu 24.04 LTS (Noble Numbat), the Linux kernel defaults to restricting unprivileged user namespaces via AppArmor:
```
sysctl kernel.apparmor_restrict_unprivileged_userns = 1
```

When this sysctl is active, any unconfined binary that attempts to invoke:
```c
unshare(CLONE_NEWUSER);
```
or `clone(..., CLONE_NEWUSER, ...)` is rejected by the AppArmor LSM with `EPERM` (`Operation not permitted`).

Tools like `bubblewrap` (`bwrap`) rely fundamentally on `CLONE_NEWUSER` to create sandbox environments without requiring setuid root binaries or sudo privileges.

## 2. Impact on UniversalRun

1. **Portable AppImage / Unpackaged Binary Execution**:
   - If UniversalRun is distributed as a standalone binary or unpacked directory running under standard user privileges on a stock Ubuntu 24.04 machine, `bwrap` execution will fail by default with:
     ```
     bwrap: Can't make symlink at /var/run: Operation not permitted
     bwrap: Setting up user namespace: Operation not permitted
     ```
2. **Debian & Fedora Behavior**:
   - **Debian 12/Testing**: Unprivileged user namespaces are permitted by default (`kernel.unprivileged_userns_clone = 1`), with no AppArmor namespace restriction.
   - **Fedora 39/40/41**: Unprivileged user namespaces are permitted by default; SELinux enforces fine-grained policy rather than blocking `CLONE_NEWUSER`.

## 3. Workarounds and Solutions

### Solution A: Install an AppArmor Profile via `.deb` Package (Recommended for MVP)
When UniversalRun is installed via its native `.deb` package (or system installer), it registers an AppArmor profile in `/etc/apparmor.d/universalrun`:

```apparmor
abi <abi/4.0>,
include <tunables/global>

profile universalrun /usr/bin/universalrun flags=(attach_disconnected) {
  include <abstractions/base>
  include <abstractions/nameservice>

  # Allow user namespace creation for the sandbox
  userns,

  # Allow executing bubblewrap
  /usr/bin/bwrap mrix,
  
  # Allow execution of wine within the sandbox
  /usr/bin/wine* mrix,
  /usr/lib*/** mrix,
}
```

Ubuntu 24.04 recognizes the `userns` permission flag and permits user namespace creation specifically for the confined binary.

### Solution B: Host-wide Sysctl Configuration (Manual / Developer Mode)
For users running standalone or development builds without installing the `.deb`:
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```
Or persistently via `/etc/sysctl.d/99-universalrun-userns.conf`:
```
kernel.apparmor_restrict_unprivileged_userns = 0
```

### Solution C: Setuid Bubblewrap Fallback
Some distributions ship `/usr/bin/bwrap` with setuid root (`chmod u+s /usr/bin/bwrap`). If setuid is present, bubblewrap can initialize namespaces even if unprivileged clone is blocked. However, UniversalRun does NOT require setuid by default to preserve defense-in-depth.

## 4. UniversalRun Pre-flight Diagnostics
UniversalRun must perform a pre-flight probe:
```rust
bwrap --unshare-user --true
```
If this exits with non-zero exit status, UniversalRun presents a clear diagnostic prompt:
- Explains that Ubuntu 24.04 restricts user namespaces.
- Provides the one-click copyable `sysctl` command or instructs the user to install the verified `.deb` package with the bundled AppArmor profile.
