# PyInstaller spec — single-file CLI executable.
# Build:  pyinstaller packaging/sentinel-cli.spec
# Output: dist/sentinel  (Linux)  /  dist/sentinel.exe  (Windows)
# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("sentinel")

a = Analysis(
    ["entry_cli.py"],
    pathex=[".."],
    binaries=[],
    datas=[("../scopes/example.json", "scopes"),
           ("../scopes/example.yaml", "scopes")],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="sentinel",
    console=True,            # CLI app
    upx=True,
    strip=False,
)
