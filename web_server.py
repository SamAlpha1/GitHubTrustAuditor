from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from trust_auditor.cli import audit_account
from trust_auditor.github_client import GitHubAPIError
from trust_auditor.web import normalize_github_target, to_jsonable

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
MAX_REQUEST_BYTES = 8_192
CACHE_TTL_SECONDS = 300
MIN_REPEAT_SECONDS = 8

_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_LAST_REQUEST: dict[str, float] = {}
_LOCK = threading.Lock()


class AuditHandler(SimpleHTTPRequestHandler):
    server_version = "GitHubTrustAuditorWeb/1.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' https://github.com https://avatars.githubusercontent.com data:; "
            "style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'"
        )
        super().end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "service": "GitHub Trust Auditor",
                    "private_scan_enabled": bool(getattr(self.server, "allow_private", False)),
                },
            )
            return
        if parsed.path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/audit":
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return

        client_ip = self.client_address[0]
        now = time.monotonic()
        with _LOCK:
            previous = _LAST_REQUEST.get(client_ip, 0.0)
            if now - previous < MIN_REPEAT_SECONDS:
                self._json(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"error": "Please wait a few seconds before starting another scan."},
                )
                return
            _LAST_REQUEST[client_ip] = now

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid request size"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            username = normalize_github_target(str(payload.get("target", "")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        include_private = bool(payload.get("include_private", False))
        allow_private = bool(getattr(self.server, "allow_private", False))
        if include_private and not allow_private:
            self._json(HTTPStatus.FORBIDDEN, {"error": "Private scanning is disabled on this server."})
            return

        cache_key = f"{username.lower()}:{int(include_private)}"
        with _LOCK:
            cached = _CACHE.get(cache_key)
            if cached and time.monotonic() - cached[0] < CACHE_TTL_SECONDS:
                response = dict(cached[1])
                response["cached"] = True
                self._json(HTTPStatus.OK, response)
                return

        token = os.environ.get("GITHUB_TOKEN")
        try:
            report = audit_account(
                username,
                include_private=include_private,
                token=token,
                max_files=int(getattr(self.server, "max_files", 350)),
                max_file_size=int(getattr(self.server, "max_file_size", 1_000_000)),
            )
            response = {"ok": True, "cached": False, "report": to_jsonable(report)}
        except (GitHubAPIError, ValueError) as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
            return
        except Exception:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Audit failed unexpectedly. Check the server console for details."},
            )
            raise

        with _LOCK:
            _CACHE[cache_key] = (time.monotonic(), response)
        self._json(HTTPStatus.OK, response)

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the GitHub Trust Auditor web interface.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Bind port (default: 8787)")
    parser.add_argument("--allow-private", action="store_true", help="Allow authorized private-repository scans")
    parser.add_argument("--max-files", type=int, default=350, help="Maximum candidate text files per repository")
    parser.add_argument("--max-file-size", type=int, default=1_000_000, help="Maximum scanned text file size")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.port < 1 or args.port > 65535 or args.max_files < 1 or args.max_file_size < 1024:
        raise SystemExit("Invalid server or scan limits")
    if args.allow_private and not os.environ.get("GITHUB_TOKEN"):
        raise SystemExit("--allow-private requires an authorized read-only GITHUB_TOKEN")

    server = ThreadingHTTPServer((args.host, args.port), AuditHandler)
    server.allow_private = args.allow_private
    server.max_files = args.max_files
    server.max_file_size = args.max_file_size
    print(f"GitHub Trust Auditor web UI: http://{args.host}:{args.port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
