#!/bin/sh
# Installs machinemap for the current user: a command in ~/.local/bin and an entry in the app menu.
# Usage: ./install.sh            (from a clone of the repo)
#        ./install.sh --uninstall
set -eu

BIN="$HOME/.local/bin/machinemap"
DESKTOP="$HOME/.local/share/applications/machinemap.desktop"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$BIN" "$DESKTOP"
    echo "Removed machinemap. Your notes are kept in ~/.config/machinemap (delete that folder to remove them too)."
    exit 0
fi

command -v python3 >/dev/null || { echo "machinemap needs python3 (3.9 or newer)." >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "machinemap needs Python 3.9 or newer." >&2; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)/machinemap.py"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications"
chmod +x "$SRC"
ln -sf "$SRC" "$BIN"

cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=Machine Map
Comment=Everything installed and running on this machine
Exec=$BIN
Icon=utilities-system-monitor
Terminal=false
Categories=System;Monitor;
EOF

echo "Installed. Open 'Machine Map' from your app menu, or run: machinemap"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Note: add ~/.local/bin to your PATH to run it from a terminal." ;; esac
