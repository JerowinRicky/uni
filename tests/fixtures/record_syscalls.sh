#!/usr/bin/env bash
# ==============================================================================
# UniversalRun - Syscall Recording Harness
# Runs Wine under strace / perf to capture the exact system calls invoked during
# prefix bootstrap and application runtime. Used to craft the M3 seccomp filter.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="/tmp/universalrun-syscalls"
mkdir -p "${OUTPUT_DIR}"

APP="${1:-/tmp/universalrun-m0-spike/app/notepad++.exe}"
PREFIX="${2:-/tmp/universalrun-m0-spike/prefix}"

echo "[record_syscalls] Target application: ${APP}"
echo "[record_syscalls] Target prefix: ${PREFIX}"
echo "[record_syscalls] Output directory: ${OUTPUT_DIR}"

if ! command -v strace >/dev/null 2>&1; then
    echo "[record_syscalls][ERROR] 'strace' is required to record syscall profile."
    exit 1
fi

echo "[record_syscalls] Launching target app under strace (summary & timing)..."
WINEPREFIX="${PREFIX}" WINEDEBUG=-all strace \
    -f \
    -c \
    -o "${OUTPUT_DIR}/syscall_summary.txt" \
    wine "${APP}" || true

echo "[record_syscalls] Syscall profiling complete."
echo "[record_syscalls] Summary saved to: ${OUTPUT_DIR}/syscall_summary.txt"
if [ -f "${OUTPUT_DIR}/syscall_summary.txt" ]; then
    head -n 25 "${OUTPUT_DIR}/syscall_summary.txt"
fi

