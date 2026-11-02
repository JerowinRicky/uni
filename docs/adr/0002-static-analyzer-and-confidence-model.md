# ADR 0002: Static Application Analyzer, Confidence Model, and Rating Limits

## Status
**ACCEPTED**

---

## Context
UniversalRun receives arbitrary Windows executables (`.exe`) and installer packages (`.msi`). Before executing anything inside a sandbox or provisioning a Wine prefix, the system must inspect and categorize the dropped binary without executing untrusted code.

However, static analysis has fundamental visibility limits:
- It cannot enumerate DLLs loaded dynamically at runtime via `LoadLibraryA/W` or `GetProcAddress`.
- It cannot verify whether an Authenticode certificate chain is trusted without a verified certificate store.
- It cannot predict hardware-dependent graphics quirks (e.g. Vulkan feature level support on host GPU).

Furthermore, showing percentages (e.g., "85% compatible") creates false precision and erodes user trust when edge-case features fail.

---

## Architectural Decisions

### 1. Three-State Authenticode Verification
An Authenticode signature directory presence does NOT imply trust. The analyzer decomposes signature analysis into three explicit properties:
1. `signature_present`: True if the `IMAGE_DIRECTORY_ENTRY_SECURITY` directory contains a valid `WIN_CERTIFICATE` structure.
2. `file_hash_verified`: Matches authentic-hash calculations against the embedded digest (or `None` if unverified).
3. `chain_trust`: Categorized as `Trusted`, `Untrusted`, or `Unknown`. It defaults to `Unknown` until a full X.509 certificate trust store validator is integrated.
*Rule*: The UI and analyzer never describe a binary as "Signed & Verified" based on signature directory presence alone.

### 2. Multi-Tier Installer Verification
- **MSI**: Inspects OLE Compound File Binary Format (CFBF) headers *and* confirms internal Windows Installer streams (`SummaryInformation`, `Property`) using the `cfb` crate. Only confirmed table structures yield `Certain` confidence.
- **Inno Setup & NSIS**: A signature match alone yields `Likely`. Parsing header structures and extracting version numbers upgrades the finding to `Certain`.

### 3. Static Rating Ceiling Rule
- **Rule**: Without an officially signed recipe backed by verified compatibility test farm results, the **maximum possible rating for static analysis is `Good`**.
- The `Excellent` rating is strictly reserved for binaries with verified runtime test evidence.
- Rating categories are strictly qualitative: `Excellent`, `Good`, `Partial`, `Experimental`, `Unsupported`, `Unknown`.

### 4. Safety Limits and Bound Checking
To defend against malicious or malformed input without execution:
- Maximum file size cap (default 2 GB).
- Strict bounds checking on all offsets and memory slices.
- Hard caps on section counts (128 max) and import entries (4096 max).
- Automated fuzz testing ensuring malformed or truncated inputs produce structured errors and never panic.

### 5. Transparency on Unverifiable Aspects
Every report emits an explicit `unverifiable_aspects` list informing the user and supervisor of dynamic behaviors that static analysis cannot guarantee.

---

## Consequences
- Clean separation of link-time facts from runtime heuristics.
- No false guarantees about application safety or compatibility.
- Fully memory-safe static analysis in pure Rust.

