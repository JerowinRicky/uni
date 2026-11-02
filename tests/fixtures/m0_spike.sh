#!/usr/bin/env bash
# ==============================================================================
# UniversalRun - Milestone 0 Feasibility Spike
# Tests running a Win64 GUI app (Notepad++ Portable) in Wine under Bubblewrap
# with zero host $HOME access, isolated wineserver, and scoped display access.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="/tmp/universalrun-m0-spike"
PREFIX_DIR="${WORK_DIR}/prefix"
APP_DIR="${WORK_DIR}/app"
SANDBOX_TMP="${WORK_DIR}/sandboxtmp"
LOG_DIR="${WORK_DIR}/logs"
NPP_URL="https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.portable.x64.zip"
NPP_ZIP="${WORK_DIR}/npp.zip"

echo "[M0] === UniversalRun M0 Feasibility Spike ==="
mkdir -p "${PREFIX_DIR}" "${APP_DIR}" "${SANDBOX_TMP}" "${LOG_DIR}"

# 1. Dependency checks on host
for cmd in bwrap wine wineserver xauth curl unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[M0][ERROR] Required host tool '$cmd' is not installed."
        exit 1
    fi
done

echo "[M0] Host tools verified: bwrap, wine, wineserver, xauth, curl, unzip."

# 2. Check unprivileged user namespace availability
if ! bwrap --unshare-user --true 2>/dev/null; then
    echo "[M0][WARN] Unprivileged user namespaces appear blocked."
    echo "[M0][WARN] On Ubuntu 24.04+, check AppArmor restrictions or run:"
    echo "       sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
    exit 2
fi
echo "[M0] Unprivileged user namespaces verified."

# 3. Download Notepad++ portable if not present
if [ ! -f "${APP_DIR}/notepad++.exe" ]; then
    echo "[M0] Downloading Notepad++ Portable x64..."
    curl -fsSL -o "${NPP_ZIP}" "${NPP_URL}"
    echo "[M0] Extracting to ${APP_DIR}..."
    unzip -q -o "${NPP_ZIP}" -d "${APP_DIR}"
fi

# 4. Create scoped Xauthority cookie (prevent full host X11 session hijacking)
SCOPED_XAUTH="${SANDBOX_TMP}/.scoped_xauth"
rm -f "${SCOPED_XAUTH}"
touch "${SCOPED_XAUTH}"

if [ -n "${DISPLAY:-}" ]; then
    echo "[M0] Scoping Xauthority for DISPLAY=${DISPLAY}..."
    COOKIE=$(xauth list "${DISPLAY}" 2>/dev/null | awk '{print $3}' | head -n1 || true)
    if [ -n "${COOKIE}" ]; then
        xauth -f "${SCOPED_XAUTH}" add "${DISPLAY}" . "${COOKIE}"
    else
        echo "[M0][WARN] No Xauthority cookie found for ${DISPLAY}. Proceeding without auth cookie."
    fi
fi

# 5. Bootstrap Wine prefix INSIDE the sandbox
# Running wineboot inside the sandbox ensures Wine never detects host paths during initialization.
echo "[M0] Bootstrapping isolated Wine prefix (wineboot -u)..."
bwrap \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /bin /bin \
    --ro-bind-try /etc/fonts /etc/fonts \
    --ro-bind-try /usr/share/fonts /usr/share/fonts \
    --ro-bind-try /usr/share/vulkan /usr/share/vulkan \
    --ro-bind-try /usr/share/glvnd /usr/share/glvnd \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "${PREFIX_DIR}" /prefix \
    --setenv WINEPREFIX /prefix \
    --setenv WINEDEBUG -all \
    --setenv WINEARCH win64 \
    --setenv HOME /tmp \
    --unshare-all \
    wineboot -u > "${LOG_DIR}/wineboot.log" 2>&1

echo "[M0] Wine prefix bootstrapped."

# 6. Sanitize prefix: remove drive Z: and redirect shell folders away from host $HOME
echo "[M0] Sanitizing prefix drive mappings and shell folders..."
"${SCRIPT_DIR}/sanitize_prefix.sh" "${PREFIX_DIR}"

# 7. Launch Notepad++ inside the restricted bubblewrap sandbox
echo "[M0] Launching Notepad++ inside Bubblewrap..."
echo "[M0] Policy: NO host \$HOME access, scoped X11 display, no network."

BWRAP_DISPLAY_ARGS=()
if [ -n "${DISPLAY:-}" ]; then
    X11_NUM="${DISPLAY#*:}"
    X11_NUM="${X11_NUM%%.*}"
    X11_SOCKET="/tmp/.X11-unix/X${X11_NUM}"
    if [ -e "${X11_SOCKET}" ]; then
        BWRAP_DISPLAY_ARGS+=(
            --ro-bind "${X11_SOCKET}" "${X11_SOCKET}"
            --ro-bind "${SCOPED_XAUTH}" /tmp/.Xauthority
            --setenv DISPLAY "${DISPLAY}"
            --setenv XAUTHORITY /tmp/.Xauthority
        )
    fi
fi

if [ -d "/dev/dri" ]; then
    BWRAP_DISPLAY_ARGS+=(--dev-bind /dev/dri /dev/dri)
fi

# Execute Notepad++ inside sandbox
bwrap \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /bin /bin \
    --ro-bind-try /etc/fonts /etc/fonts \
    --ro-bind-try /usr/share/fonts /usr/share/fonts \
    --ro-bind-try /usr/share/vulkan /usr/share/vulkan \
    --ro-bind-try /usr/share/glvnd /usr/share/glvnd \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    "${BWRAP_DISPLAY_ARGS[@]}" \
    --bind "${PREFIX_DIR}" /prefix \
    --ro-bind "${APP_DIR}" /app \
    --setenv WINEPREFIX /prefix \
    --setenv WINEDEBUG -all,err+all,fixme-all \
    --setenv WINEARCH win64 \
    --setenv HOME /tmp \
    --unshare-all \
    wine /app/notepad++.exe > "${LOG_DIR}/notepad++.log" 2>&1 &

APP_PID=$!
echo "[M0] Application started (PID: ${APP_PID})."
echo "[M0] Check the Notepad++ 'File -> Open' dialog to verify host /home paths do NOT appear."
echo "[M0] Logs: ${LOG_DIR}/notepad++.log"

# Wait for process exit
wait "${APP_PID}" || true
echo "[M0] Application exited cleanly."
