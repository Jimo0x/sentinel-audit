# PyInstaller spec — windowed desktop GUI executable.
# Build:  pyinstaller packaging/sentinel-gui.spec
# Output: dist/sentinel-desktop (Linux) / dist/sentinel-desktop.exe (Windows)
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("sentinel")
# pywebview is optional; include it if present so the native window works.
try:
    import webview  # noqa: F401
    hiddenimports += collect_submodules("webview")
except Exception:
    pass

a = Analysis(
    ["entry_gui.py"],
    pathex=[".."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="sentinel-desktop",
    console=False,           # windowed app (no console)
    upx=True,
    strip=False,
)
