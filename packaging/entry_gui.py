"""PyInstaller entry point for the desktop GUI build.

Bundled as a windowed app; launches the native/browser desktop UI.
"""
from sentinel.desktop import launch

if __name__ == "__main__":
    raise SystemExit(launch())
