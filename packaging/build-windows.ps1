# Build native Windows executables (CLI + desktop).
#
# Prereqs:  py -m pip install pyinstaller pywebview
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File packaging\build-windows.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host ">> Building CLI executable..."
pyinstaller --noconfirm --distpath dist --workpath build\cli packaging\sentinel-cli.spec

Write-Host ">> Building desktop GUI executable..."
pyinstaller --noconfirm --distpath dist --workpath build\gui packaging\sentinel-gui.spec

Write-Host ">> Artifacts:"
Get-ChildItem dist\sentinel.exe, dist\sentinel-desktop.exe -ErrorAction SilentlyContinue |
  Select-Object Name, Length

Write-Host ">> Done. Executables are in .\dist"
