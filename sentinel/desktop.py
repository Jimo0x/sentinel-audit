"""Native desktop launcher for the Sentinel GUI.

Runs the local web UI server and shows it in a native OS window via `pywebview`
when that optional dependency is installed. Without it, Sentinel degrades
gracefully to opening the UI in the default browser — the same experience,
just in a browser tab.

This is what the packaged desktop app (PyInstaller) launches.
"""
from __future__ import annotations

import threading
import time
from http.server import ThreadingHTTPServer

from sentinel import __version__
from sentinel.gui.app import Handler


def _start_server(host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def launch(host: str = "127.0.0.1", port: int = 8787) -> int:
    """Launch the desktop app: native window if possible, else browser."""
    httpd = _start_server(host, port)
    url = f"http://{host}:{port}/"
    try:
        import webview  # pywebview, optional
    except ModuleNotFoundError:
        # Fall back to the browser-based server loop.
        import webbrowser
        print(f"Sentinel Audit {__version__} — desktop UI at {url}")
        print("(install 'pywebview' for a native window; opening your browser instead)")
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down.")
        finally:
            httpd.shutdown()
        return 0

    # Native window path.
    window = webview.create_window(
        f"Sentinel Audit {__version__}", url,
        width=1100, height=720, min_size=(820, 560),
        background_color="#0f1115",
    )
    try:
        webview.start()
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
