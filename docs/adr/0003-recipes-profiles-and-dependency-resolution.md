# ADR 0003: Recipes, Profiles, and Hardened Dependency Resolution

## Status
Accepted

## Context
UniversalRun requires deterministic, reproducible application profiles configured without manual Wine/prefix tweaking. To avoid becoming an insecure wrapper, the platform must guarantee:
1. Profiles are strictly declarative and fully rebuildable from the manifest alone.
2. Third-party recipes are data-only (no executable scripts) and cryptographically signed.
3. Path inputs, manifests, and catalog entries are treated as untrusted, preventing container escapes, ambient `$HOME` access, and host path traversal.
4. Third-party runtime dependencies are strictly verified against cryptographic hashes before being executed or applied.

## Decisions

### 1. Declarative Profile Manifest and Storage
- **Manifest Alone**: A profile's configuration is fully specified by `ProfileManifest` (TOML/JSON). It records pinned runtime versions, architecture, dependencies, environment variables, DLL overrides, filesystem mappings, and hardware permission flags.
- **Deterministic Rebuild Hash**: Each manifest computes a SHA-256 digest over its canonical fields (excluding `rebuild_hash` itself), ensuring bit-for-bit rebuild integrity.
- **XDG Storage Paths**: Profile storage paths default to OS standard directories via the `directories` crate (`~/.local/share/universalrun/profiles/` on Linux; `%LOCALAPPDATA%/universalrun/profiles/` on Windows).
- **Downgrade Protection**: Rebuilding or updating an existing profile with an older recipe revision is strictly rejected unless the user explicitly passes `--allow-older`, which logs an audible security warning.

### 2. Path Validation and Sanitization at Use Time
- All host and guest filesystem mappings are re-validated and canonicalized at use time.
- Symlinks are unconditionally rejected to prevent symlink-following attacks out of sandboxed mounts.
- Host path traversal (`..`), references to `$HOME`, `~`, and root mounts (`/`, `\`) are strictly forbidden.
- Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`) are rejected case-insensitively across path components.
- Unicode normalization, zero-width characters, bidirectional override codepoints, and ASCII control characters are rejected.
- Case collisions within mapped directories are detected and blocked.

### 3. Cryptographic Recipe Verification and Dev Policy
- **Data Only**: Recipes contain zero shell scripts, bash commands, or procedural hooks.
- **Ed25519 Signatures**: Signed recipes carry an Ed25519 signature and a `key_id` identifying the trusted public key in a key registry, facilitating rotation.
- **Canonical Bytes**: The exact bytes signed are defined as compact, recursively key-sorted canonical JSON bytes of the recipe with the `signature` field stripped.
- **Key Separation**: A separate development key (`ur-dev-key`) is used for local authoring. Release builds (`not(debug_assertions)`) strictly refuse any signature matching `ur-dev-key`.
- **Unsigned Recipes**: Permitted *only* when residing in the designated local development directory (`recipes/dev/`) and trigger a prominent security warning banner. Unsigned recipes from any other directory or external source are rejected.
- **Precedence**: Exact SHA-256 match > Product name/version range match > Synthesized generic fallback.

### 4. Hardened Dependency Resolver
- **Zero Fabricated Hashes**: Unknown dependency hashes are kept as literal `"TODO"`. The resolver unconditionally rejects any dependency marked with `"TODO"`.
- **HTTPS Enforcement**: Dependency download URLs must use `https://`. Every redirect hop is inspected; any non-HTTPS redirect is rejected.
- **Per-Dependency Size Caps**: Each dependency declares a `max_size_bytes` limit in `dependencies.toml`. Streaming downloads are aborted immediately if this threshold is exceeded.
- **Atomic Cache Updates**: Downloads stream into a temporary `.tmp` file in the cache directory, verify their SHA-256 hash upon completion, and are atomically moved to `<sha256>.bin`. Corrupt or mismatched files are immediately unlinked.
- **Test Invariants**: Insecure test protocols are only available under `#[cfg(test)]` and never accessible in runtime builds.

### 5. Runtime Backend Call Sites
- Wine process execution remains strictly out of scope for M2. `universalrun plan` generates and displays execution plans and dependency requirements without creating prefixes or launching Wine.
- Milestone 0 feasibility spike remains **PROVISIONAL** pending real Linux host test verification.

## Consequences
- **Positive**: Complete defense against remote code execution via malicious recipes; no ambient filesystem access; reproducible builds; strict dependency verification.
- **Trade-off**: Adding new community dependencies requires manual catalog maintenance and verified SHA-256 calculation.

