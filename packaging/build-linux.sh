#!/usr/bin/env bash
# Build native Linux binaries (CLI + desktop) and, if appimagetool is present,
# an AppImage for the desktop app.
#
# Prereqs:  python3 -m pip install pyinstaller pywebview
# Run from the repo root:  bash packaging/build-linux.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo ">> Building CLI binary..."
pyinstaller --noconfirm --distpath dist --workpath build/cli packaging/sentinel-cli.spec

echo ">> Building desktop GUI binary..."
pyinstaller --noconfirm --distpath dist --workpath build/gui packaging/sentinel-gui.spec

echo ">> Binaries:"
ls -lh dist/sentinel dist/sentinel-desktop 2>/dev/null || true

# Optional: assemble an AppImage for the desktop app.
if command -v appimagetool >/dev/null 2>&1; then
  echo ">> Assembling AppImage..."
  APPDIR=build/SentinelAudit.AppDir
  rm -rf "$APPDIR"; mkdir -p "$APPDIR/usr/bin"
  cp dist/sentinel-desktop "$APPDIR/usr/bin/"
  cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/sentinel-desktop" "$@"
EOF
  chmod +x "$APPDIR/AppRun"
  cat > "$APPDIR/sentinel-audit.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Sentinel Audit
Exec=sentinel-desktop
Icon=sentinel-audit
Categories=Security;Network;
Terminal=false
EOF
  # a minimal placeholder icon (1x1 png) keeps appimagetool happy
  printf '\x89PNG\r\n\x1a\n' > "$APPDIR/sentinel-audit.png"
  appimagetool "$APPDIR" dist/SentinelAudit-x86_64.AppImage || echo "AppImage step failed (non-fatal)"
else
  echo ">> appimagetool not found — skipping AppImage (CLI/desktop binaries still built)."
fi

echo ">> Done. Artifacts in ./dist"
