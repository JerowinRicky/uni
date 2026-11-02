#!/usr/bin/env bash
# ==============================================================================
# UniversalRun - Milestone 0 Feasibility Spike Harness
# Target Environment: Linux x86_64 (e.g., Ubuntu 24.04, Debian 12, Fedora 40)
#
# Tests and gathers evidence for:
# 1. Unprivileged user namespace restrictions (Ubuntu 24.04 AppArmor)
# 2. Wineboot execution inside Bubblewrap sandbox
# 3. Z: drive elimination and shell-folder symlink sanitization
# 4. Exit code and crash propagation through Bubblewrap
# 5. Live GUI launch of Notepad++ Portable x64 without host $HOME
# 6. Process lifecycle verification (zero orphan wineserver/wine processes)
# ==============================================================================
set -u

WORK_DIR="/tmp/universalrun-m0-spike"
PREFIX_DIR="${WORK_DIR}/prefix"
APP_DIR="${WORK_DIR}/app"
SANDBOX_TMP="${WORK_DIR}/sandboxtmp"
LOG_DIR="${WORK_DIR}/logs"
NPP_URL="https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.9/npp.8.6.9.portable.x64.zip"
NPP_ZIP="${WORK_DIR}/npp.zip"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_section() {
    echo ""
    echo "======================================================================"
    echo " [TEST] $1"
    echo "======================================================================"
}

log_result() {
    local status="$1"
    local desc="$2"
    echo "[RESULT] [${status}] ${desc}"
}

mkdir -p "${PREFIX_DIR}" "${APP_DIR}" "${SANDBOX_TMP}" "${LOG_DIR}"

log_section "Host Environment & Prerequisites"
echo "Host Kernel: $(uname -s -r -m)"
if [ -f /etc/os-release ]; then
    grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release || true
fi

for cmd in bwrap wine wineserver xauth curl unzip pgrep; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "Tool available: $cmd ($(command -v "$cmd"))"
    else
        echo "MISSING tool: $cmd"
        log_result "FAIL" "Prerequisite '$cmd' is missing."
        exit 1
    fi
done
log_result "PASS" "All required host tools are installed."


log_section "Test 1: Unprivileged User Namespace Probe (Ubuntu 24.04 AppArmor check)"
echo "Command: bwrap --unshare-user --true"
bwrap --unshare-user --true 2> "${LOG_DIR}/userns_probe.err"
USERNS_EXIT=$?
echo "Exit code: ${USERNS_EXIT}"

if [ ${USERNS_EXIT} -eq 0 ]; then
    log_result "PASS" "Unprivileged user namespaces are functional."
else
    log_result "BLOCKED" "Unprivileged user namespaces blocked by kernel/AppArmor."
    cat "${LOG_DIR}/userns_probe.err"
    echo ""
    echo "--> If on Ubuntu 24.04, run:"
    echo "    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
    echo "    and re-run this script to test with workaround enabled."
    exit 2
fi


log_section "Test 2: Download & Prepare Target Application (Notepad++ Portable x64)"
if [ ! -f "${APP_DIR}/notepad++.exe" ]; then
    echo "Downloading: ${NPP_URL}"
    curl -fsSL -o "${NPP_ZIP}" "${NPP_URL}"
    echo "Extracting to: ${APP_DIR}"
    unzip -q -o "${NPP_ZIP}" -d "${APP_DIR}"
fi

if [ -f "${APP_DIR}/notepad++.exe" ]; then
    log_result "PASS" "Notepad++ x64 binary ready: ${APP_DIR}/notepad++.exe"
else
    log_result "FAIL" "Failed to acquire Notepad++ binary."
    exit 1
fi


log_section "Test 3: Wineboot Execution Inside Bubblewrap Sandbox"
echo "Bootstrapping prefix strictly inside sandbox with throwaway HOME=/tmp..."
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
WINEBOOT_EXIT=$?
echo "Exit code: ${WINEBOOT_EXIT}"

if [ ${WINEBOOT_EXIT} -eq 0 ]; then
    log_result "PASS" "wineboot -u completed cleanly inside sandbox."
else
    log_result "FAIL" "wineboot failed inside sandbox. Inspect ${LOG_DIR}/wineboot.log"
    exit 1
fi


log_section "Test 4: Prefix Sanitization & Host Path Elimination"
echo "Running sanitize_prefix.sh on: ${PREFIX_DIR}"
"${SCRIPT_DIR}/sanitize_prefix.sh" "${PREFIX_DIR}"

echo "Verifying dosdevices contents:"
ls -la "${PREFIX_DIR}/dosdevices"

if [ -e "${PREFIX_DIR}/dosdevices/z:" ]; then
    log_result "FAIL" "dosdevices/z: STILL EXISTS!"
else
    log_result "PASS" "dosdevices/z: is completely absent."
fi

echo "Verifying absence of symlinks to host directories in drive_c/users:"
LEAKED_LINKS=0
while IFS= read -r -d '' link; do
    target="$(readlink -f "$link" || true)"
    if [[ "$target" != "${PREFIX_DIR}"* ]]; then
        echo "LEAK DETECTED: $link -> $target"
        LEAKED_LINKS=$((LEAKED_LINKS + 1))
    fi
done < <(find "${PREFIX_DIR}/drive_c/users" -type l -print0 2>/dev/null)

if [ "${LEAKED_LINKS}" -eq 0 ]; then
    log_result "PASS" "Zero symlinks pointing outside prefix found."
else
    log_result "FAIL" "${LEAKED_LINKS} external symlinks detected in prefix."
fi


log_section "Test 5: Exit Code & Crash Propagation"
echo "Subtest 5a: Deliberate non-zero exit code (cmd /c exit 42)"
bwrap \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /bin /bin \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "${PREFIX_DIR}" /prefix \
    --setenv WINEPREFIX /prefix \
    --setenv WINEDEBUG -all \
    --setenv HOME /tmp \
    --unshare-all \
    wine cmd.exe /c exit 42 > /dev/null 2>&1
CRASH_EXIT=$?
echo "Observed exit code: ${CRASH_EXIT} (Expected: 42)"

if [ "${CRASH_EXIT}" -eq 42 ]; then
    log_result "PASS" "Exit code 42 propagated accurately through bwrap."
else
    log_result "FAIL" "Exit code mismatch: got ${CRASH_EXIT}, expected 42."
fi

echo "Subtest 5b: Executing non-existent binary in sandbox"
bwrap \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /bin /bin \
    --dev /dev \
    --proc /proc \
    --tmpfs /tmp \
    --bind "${PREFIX_DIR}" /prefix \
    --setenv WINEPREFIX /prefix \
    --setenv WINEDEBUG -all \
    --setenv HOME /tmp \
    --unshare-all \
    wine /app/nonexistent_file_xyz.exe > /dev/null 2>&1
MISSING_EXIT=$?
echo "Observed exit code: ${MISSING_EXIT} (Expected non-zero)"

if [ "${MISSING_EXIT}" -ne 0 ]; then
    log_result "PASS" "Missing binary exit failure cleanly propagated."
else
    log_result "FAIL" "Expected non-zero exit code, got 0."
fi


log_section "Test 6: Live GUI Launch (Notepad++ Portable x64 without host \$HOME)"
SCOPED_XAUTH="${SANDBOX_TMP}/.scoped_xauth"
rm -f "${SCOPED_XAUTH}"
touch "${SCOPED_XAUTH}"

BWRAP_DISPLAY_ARGS=()
if [ -n "${DISPLAY:-}" ]; then
    X11_NUM="${DISPLAY#*:}"
    X11_NUM="${X11_NUM%%.*}"
    X11_SOCKET="/tmp/.X11-unix/X${X11_NUM}"
    if [ -e "${X11_SOCKET}" ]; then
        COOKIE=$(xauth list "${DISPLAY}" 2>/dev/null | awk '{print $3}' | head -n1 || true)
        if [ -n "${COOKIE}" ]; then
            xauth -f "${SCOPED_XAUTH}" add "${DISPLAY}" . "${COOKIE}"
            BWRAP_DISPLAY_ARGS+=(
                --ro-bind "${SCOPED_XAUTH}" /tmp/.Xauthority
                --setenv XAUTHORITY /tmp/.Xauthority
            )
        fi
        BWRAP_DISPLAY_ARGS+=(
            --ro-bind "${X11_SOCKET}" "${X11_SOCKET}"
            --setenv DISPLAY "${DISPLAY}"
        )
    fi
fi

if [ -d "/dev/dri" ]; then
    BWRAP_DISPLAY_ARGS+=(--dev-bind /dev/dri /dev/dri)
fi

echo "Launching Notepad++ GUI inside sandbox..."
echo "--> ACTION REQUIRED: When Notepad++ opens:"
echo "    1. Click 'File -> Open' (Ctrl+O)."
echo "    2. Verify in the drive dropdown / explorer tree that NO host Linux paths or host /home paths appear."
echo "    3. Close Notepad++ to complete this test."

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
    wine /app/notepad++.exe > "${LOG_DIR}/notepad++.log" 2>&1
GUI_EXIT=$?
echo "Notepad++ exited with code: ${GUI_EXIT}"


log_section "Test 7: Wineserver & Child Process Teardown Verification"
echo "Checking for any lingering wineserver or wine processes on the host..."
sleep 2 # allow brief settling time for teardown

RUNNING_WINESERVER=$(pgrep -a wineserver || true)
RUNNING_WINE=$(pgrep -a wine || true)

if [ -z "${RUNNING_WINESERVER}" ] && [ -z "${RUNNING_WINE}" ]; then
    log_result "PASS" "Zero orphan wineserver or wine processes found on host."
else
    log_result "FAIL" "Orphan processes still running on host:"
    [ -n "${RUNNING_WINESERVER}" ] && echo "${RUNNING_WINESERVER}"
    [ -n "${RUNNING_WINE}" ] && echo "${RUNNING_WINE}"
fi

log_section "Spike Execution Summary"
echo "Spike test run complete. Please copy this entire log and report results."
