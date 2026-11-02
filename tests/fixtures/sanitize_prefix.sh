#!/usr/bin/env bash
# ==============================================================================
# UniversalRun - Prefix Sanitization Script
# Eliminates host path leaks:
# 1. Removes Z: drive symlink (which points to root '/')
# 2. Replaces Windows Shell Folders (Desktop, Documents, etc.) with local folders
#    inside C:\users\<user>\ instead of symlinks pointing to host /home/<user>
# ==============================================================================
set -euo pipefail

PREFIX="${1:-}"

if [ -z "${PREFIX}" ] || [ ! -d "${PREFIX}" ]; then
    echo "Usage: $0 <path_to_wine_prefix>"
    exit 1
fi

echo "[sanitize_prefix] Processing prefix: ${PREFIX}"

# 1. Remove Z: drive mapping (points to '/')
if [ -L "${PREFIX}/dosdevices/z:" ] || [ -e "${PREFIX}/dosdevices/z:" ]; then
    rm -f "${PREFIX}/dosdevices/z:"
    echo "[sanitize_prefix] Removed dosdevices/z: symlink."
fi

# 2. Inspect users directory and remove symlinks to host directories
USERS_DIR="${PREFIX}/drive_c/users"
if [ -d "${USERS_DIR}" ]; then
    find "${USERS_DIR}" -type l | while read -r symlink; do
        target="$(readlink -f "$symlink" || true)"
        # If target points outside the prefix, replace it with a real local directory
        if [[ "$target" != "${PREFIX}"* ]]; then
            echo "[sanitize_prefix] Replacing external symlink: $symlink -> $target"
            rm -f "$symlink"
            mkdir -p "$symlink"
        fi
    done
fi

# 3. Patch Wine registry to redirect Windows Explorer Shell Folders internally
REG_FILE="$(mktemp /tmp/user_folders_XXXXXX.reg)"
cat << 'EOF' > "${REG_FILE}"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders]
"Desktop"="%USERPROFILE%\\Desktop"
"Personal"="%USERPROFILE%\\Documents"
"My Pictures"="%USERPROFILE%\\Pictures"
"My Music"="%USERPROFILE%\\Music"
"My Video"="%USERPROFILE%\\Videos"
"Downloads"="%USERPROFILE%\\Downloads"
"Favorites"="%USERPROFILE%\\Favorites"
EOF

# Apply the registry patch if wine is functional in this context
if command -v wine >/dev/null 2>&1; then
    WINEPREFIX="${PREFIX}" WINEDEBUG=-all wine regedit /S "${REG_FILE}" 2>/dev/null || true
fi
rm -f "${REG_FILE}"

echo "[sanitize_prefix] Prefix sanitization complete."
