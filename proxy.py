#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hyperproxy — a dependency-free, asyncio HTTP/1.1 forward proxy.

Features
--------
* Full HTTP/1.1 forward proxying (absolute-form request targets)
* HTTPS via the CONNECT method (tunnels), plus absolute-form https:// targets
* Correct hop-by-hop header handling (RFC 7230)
* Request/response body framing: Content-Length, chunked, close-delimited
* HTTP keep-alive on the client side, connection pooling to origins
* WebSocket / protocol upgrades (101 Switching Protocols)
* Optional Basic proxy authentication (Proxy-Authorization)
* Optional per-IP token-bucket rate limiting
* Optional SSRF guard that blocks private / loopback / link-local targets
* Graceful shutdown, structured access logs, Prometheus-style metrics
* Admin HTTP endpoint: /healthz, /stats, /metrics

Usage
-----
    python3 proxy.py --port 8080 --admin-port 9090 --user me --password secret

Then:
    curl -x http://me:secret@127.0.0.1:8080 https://example.com
    curl -x http://me:secret@127.0.0.1:8080 http://example.com
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import logging
import os
import select
import signal
import socket
import ssl
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

SERVER_NAME = "hyperproxy"
SERVER_VERSION = "1.0.0"

CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"
CHUNK_SIZE = 64 * 1024

# Classic hop-by-hop headers (RFC 2616 §13.5.1 / RFC 7230 §6.1).
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "transfer-encoding",
        "upgrade",
    }
)

STATUS_REASONS = {
    100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
    200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
    204: "No Content", 205: "Reset Content", 206: "Partial Content",
    300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
    304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
    407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
    410: "Gone", 411: "Length Required", 412: "Precondition Failed",
    413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
    416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
    421: "Misdirected Request", 422: "Unprocessable Entity", 425: "Too Early",
    426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests",
    431: "Request Header Fields Too Large", 451: "Unavailable For Legal Reasons",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout", 505: "HTTP Version Not Supported",
    507: "Insufficient Storage", 508: "Loop Detected", 511: "Network Authentication Required",
}


def reason_phrase(status: int) -> str:
    return STATUS_REASONS.get(status, "Unknown")


# --------------------------------------------------------------------------- #
#  Logging
# --------------------------------------------------------------------------- #


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[1;41m",
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, use_color: bool):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if self.use_color and sys.stderr.isatty():
            color = self.COLORS.get(record.levelno)
            if color:
                return f"{color}{text}{self.RESET}"
        return text


LOG = logging.getLogger("hyperproxy")


def setup_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        ColorFormatter("%(asctime)s %(levelname)-7s %(message)s", use_color=True)
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# --------------------------------------------------------------------------- #
#  Errors
# --------------------------------------------------------------------------- #


class ProxyError(Exception):
    """An error that should be turned into an HTTP response for the client."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.reason = message


# --------------------------------------------------------------------------- #
#  Header container
# --------------------------------------------------------------------------- #


class Headers:
    """Ordered, case-insensitive multimap of HTTP headers."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[Tuple[str, str]] = ()):
        self._items: List[Tuple[str, str]] = [(k.lower(), v) for k, v in items]

    # -- accessors -------------------------------------------------------- #

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        name = name.lower()
        for k, v in self._items:
            if k == name:
                return v
        return default

    def get_all(self, name: str) -> List[str]:
        name = name.lower()
        return [v for k, v in self._items if k == name]

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    # -- mutators --------------------------------------------------------- #

    def add(self, name: str, value: str) -> None:
        self._items.append((name.lower(), value))

    def set(self, name: str, value: str) -> None:
        name = name.lower()
        self._items = [(k, v) for k, v in self._items if k != name]
        self._items.append((name, value))

    def remove(self, name: str) -> None:
        name = name.lower()
        self._items = [(k, v) for k, v in self._items if k != name]

    # -- helpers ---------------------------------------------------------- #

    def connection_tokens(self) -> set:
        """Header names listed in the Connection header (hop-by-hop markers)."""
        tokens = set()
        for value in self.get_all("connection"):
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
        return tokens

    def to_bytes(self) -> bytes:
        out = bytearray()
        for k, v in self._items:
            out += k.encode("latin-1", "replace")
            out += b": "
            out += v.encode("latin-1", "replace")
            out += CRLF
        out += CRLF
        return bytes(out)


# --------------------------------------------------------------------------- #
#  Parsing helpers
# --------------------------------------------------------------------------- #


def to_ascii_host(host: str) -> str:
    """IDNA-encode non-ASCII hostnames."""
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        return host.encode("idna").decode("ascii")


def split_authority(authority: str, default_port: int) -> Tuple[str, int]:
    """Split "host:port" / "[v6]:port" / "host" into (host, port)."""
    authority = authority.strip()
    if authority.startswith("["):  # IPv6 literal
        host, _, rest = authority[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    host, sep, port = authority.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return authority, default_port


def format_authority(host: str, port: int, tls: bool) -> str:
    disp = f"[{host}]" if ":" in host else host
    default = 443 if tls else 80
    return disp if port == default else f"{disp}:{port}"


def parse_head(head: bytes) -> Tuple[bytes, Headers]:
    """Split a raw header block into (start_line, Headers)."""
    lines = head[: -len(HEADER_END)].split(CRLF)
    start_line = lines[0] if lines else b""
    items: List[Tuple[str, str]] = []
    for raw in lines[1:]:
        if not raw:
            continue
        if raw[:1] in (b" ", b"\t"):
            # obs-fold continuation
            if items:
                k, v = items[-1]
                items[-1] = (k, v + " " + raw.strip().decode("latin-1"))
            continue
        name, sep, value = raw.partition(b":")
        if not sep:
            raise ProxyError(400, "Malformed header line")
        items.append(
            (name.strip().decode("latin-1"), value.strip().decode("latin-1"))
        )
    return start_line, Headers(items)


def parse_request_line(line: bytes) -> Tuple[str, str, str]:
    parts = line.decode("latin-1").split()
    if len(parts) != 3:
        raise ProxyError(400, "Malformed request line")
    method, target, version = parts
    if not version.startswith("HTTP/"):
        raise ProxyError(400, "Unsupported protocol version")
    return method.upper(), target, version.upper()


def parse_status_line(line: bytes) -> Tuple[str, int, str]:
    parts = line.decode("latin-1").split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ProxyError(502, "Malformed status line from upstream")
    try:
        status = int(parts[1])
    except ValueError:
        raise ProxyError(502, "Malformed status code from upstream") from None
    reason = parts[2] if len(parts) > 2 else reason_phrase(status)
    return parts[0], status, reason


async def read_head(reader: asyncio.StreamReader, max_bytes: int) -> Optional[bytes]:
    """Read a header block terminated by CRLFCRLF. Returns None on clean EOF."""
    try:
        head = await reader.readuntil(HEADER_END)
    except asyncio.IncompleteReadError:
        return None
    except asyncio.LimitOverrunError as exc:
        raise ProxyError(431, "Request Header Fields Too Large") from exc
    if len(head) > max_bytes:
        raise ProxyError(431, "Request Header Fields Too Large")
    return head


async def is_private_host(host: str) -> bool:
    """Resolve `host` and report whether any address is non-public."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


# --------------------------------------------------------------------------- #
#  Body relays
# --------------------------------------------------------------------------- #


async def relay_exactly(src: asyncio.StreamReader, dst: asyncio.StreamWriter, n: int) -> int:
    remaining, total = n, 0
    while remaining > 0:
        chunk = await src.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise asyncio.IncompleteReadError(b"", remaining)
        dst.write(chunk)
        await dst.drain()
        remaining -= len(chunk)
        total += len(chunk)
    return total


async def relay_until_eof(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
    total = 0
    while True:
        chunk = await src.read(CHUNK_SIZE)
        if not chunk:
            return total
        dst.write(chunk)
        await dst.drain()
        total += len(chunk)


async def relay_chunked(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> int:
    """Relay a chunked transfer body verbatim, including trailers."""
    total = 0
    while True:
        line = await src.readuntil(CRLF)
        if len(line) > 8192:
            raise ValueError("chunk header too long")
        dst.write(line)
        size_field = line.split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            raise ValueError(f"bad chunk size {size_field!r}") from None
        if size < 0:
            raise ValueError("negative chunk size")
        if size == 0:
            while True:
                trailer = await src.readuntil(CRLF)
                dst.write(trailer)
                if trailer == CRLF:
                    break
            await dst.drain()
            return total
        payload = await src.readexactly(size + 2)  # data + CRLF
        dst.write(payload)
        await dst.drain()
        total += size


async def relay_body(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    mode: str,
    length: int = 0,
) -> int:
    if mode == "none":
        return 0
    if mode == "length":
        return await relay_exactly(src, dst, length)
    if mode == "chunked":
        return await relay_chunked(src, dst)
    return await relay_until_eof(src, dst)


# --------------------------------------------------------------------------- #
#  Statistics
# --------------------------------------------------------------------------- #


class Stats:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.active_connections = 0
        self.total_connections = 0
        self.requests = 0
        self.tunnels = 0
        self.errors = 0
        self.blocked = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.status_counts: Dict[str, int] = defaultdict(int)

    def snapshot(self) -> dict:
        return {
            "version": SERVER_VERSION,
            "uptime_seconds": round(time.time() - self.started_at, 2),
            "active_connections": self.active_connections,
            "total_connections": self.total_connections,
            "requests": self.requests,
            "tunnels": self.tunnels,
            "errors": self.errors,
            "blocked": self.blocked,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "status_counts": dict(sorted(self.status_counts.items())),
        }


# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 8080
    admin_port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    max_header_bytes: int = 65536
    connect_timeout: float = 15.0
    idle_timeout: float = 120.0
    read_timeout: float = 60.0
    upstream_idle_timeout: float = 30.0
    pool_size: int = 8
    rate_limit: float = 0.0
    rate_burst: float = 0.0
    block_private: bool = False
    verbose: bool = False


# --------------------------------------------------------------------------- #
#  The proxy
# --------------------------------------------------------------------------- #


class HyperProxy:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.stats = Stats()
        self.pool: Dict[
            Tuple[str, int, bool],
            List[Tuple[float, asyncio.StreamReader, asyncio.StreamWriter]],
        ] = defaultdict(list)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._shutdown = asyncio.Event()
        self._servers: List[asyncio.AbstractServer] = []
        self._tasks: List[asyncio.Task] = []

        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.set_alpn_protocols(["http/1.1"])

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        server = await asyncio.start_server(
            self.handle_client,
            host=self.cfg.host,
            port=self.cfg.port,
            limit=self.cfg.max_header_bytes,
            reuse_address=True,
        )
        self._servers.append(server)
        for sock in server.sockets or ():
            LOG.info("proxy listening on %s:%d", sock.getsockname()[0], sock.getsockname()[1])

        if self.cfg.admin_port:
            admin = await asyncio.start_server(
                self.handle_admin,
                host=self.cfg.host,
                port=self.cfg.admin_port,
                limit=16384,
                reuse_address=True,
            )
            self._servers.append(admin)
            LOG.info("admin endpoint on %s:%d", self.cfg.host, self.cfg.admin_port)

        self._tasks.append(asyncio.create_task(self._janitor()))
        if self.cfg.username:
            LOG.info("proxy authentication ENABLED (user=%s)", self.cfg.username)
        else:
            LOG.warning("proxy authentication DISABLED — anyone can use this proxy")
        if self.cfg.rate_limit > 0:
            LOG.info(
                "rate limit: %g req/s per IP (burst %g)",
                self.cfg.rate_limit,
                self.cfg.rate_burst or self.cfg.rate_limit,
            )

    async def serve_forever(self) -> None:
        await self._shutdown.wait()

    async def stop(self) -> None:
        self._shutdown.set()
        for server in self._servers:
            server.close()
        for server in self._servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        for task in self._tasks:
            task.cancel()
        for bucket in self.pool.values():
            for _, _, writer in bucket:
                with contextlib.suppress(Exception):
                    writer.close()
        self.pool.clear()
        LOG.info("shutdown complete")

    # ------------------------------------------------------------------ #
    #  Background maintenance
    # ------------------------------------------------------------------ #

    async def _janitor(self) -> None:
        try:
            while True:
                await asyncio.sleep(5)
                now = time.monotonic()
                # Expire idle pooled connections.
                for key in list(self.pool.keys()):
                    bucket = self.pool.get(key) or []
                    keep = []
                    for ts, reader, writer in bucket:
                        if now - ts > self.cfg.upstream_idle_timeout or writer.is_closing():
                            self._kill(reader, writer)
                        else:
                            keep.append((ts, reader, writer))
                    if keep:
                        self.pool[key] = keep
                    else:
                        self.pool.pop(key, None)
                # Expire rate-limit buckets.
                if self._buckets:
                    for ip in list(self._buckets.keys()):
                        tokens, last = self._buckets[ip]
                        if now - last > 300:
                            self._buckets.pop(ip, None)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------ #
    #  Admission control
    # ------------------------------------------------------------------ #

    def _allow(self, ip: str) -> bool:
        if self.cfg.rate_limit <= 0:
            return True
        burst = self.cfg.rate_burst or self.cfg.rate_limit
        now = time.monotonic()
        tokens, last = self._buckets.get(ip, (burst, now))
        tokens = min(burst, tokens + (now - last) * self.cfg.rate_limit)
        if tokens < 1.0:
            self._buckets[ip] = (tokens, now)
            return False
        self._buckets[ip] = (tokens - 1.0, now)
        return True

    def _check_auth(self, headers: Headers) -> None:
        if not self.cfg.username:
            return
        value = headers.get("proxy-authorization")
        ok = False
        if value and value.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(value[6:].strip(), validate=True).decode("utf-8")
            except Exception:
                decoded = ""
            user, _, password = decoded.partition(":")
            ok = hmac.compare_digest(user, self.cfg.username) and hmac.compare_digest(
                password, self.cfg.password or ""
            )
        if not ok:
            raise ProxyError(407, "Proxy Authentication Required")

    # ------------------------------------------------------------------ #
    #  Client entrypoint
    # ------------------------------------------------------------------ #

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if isinstance(peer, tuple) and peer else "unknown"
        conn_id = uuid.uuid4().hex[:12]

        self.stats.active_connections += 1
        self.stats.total_connections += 1
        try:
            await self._session(reader, writer, conn_id, peer_ip)
        except ProxyError as exc:
            self.stats.errors += 1
            self.stats.status_counts[str(exc.status)] += 1
            await self._safe_write(writer, error_response(exc.status, exc.reason))
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await self._safe_write(writer, error_response(408, "Request Timeout"))
        except Exception as exc:  # noqa: BLE001
            self.stats.errors += 1
            LOG.exception("[%s] unhandled error: %s", conn_id, exc)
            await self._safe_write(writer, error_response(500, "Internal Proxy Error"))
        finally:
            self.stats.active_connections -= 1
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 2.0)

    async def _session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: str,
        peer_ip: str,
    ) -> None:
        while True:
            head = await asyncio.wait_for(
                read_head(reader, self.cfg.max_header_bytes), self.cfg.idle_timeout
            )
            if head is None:
                return  # client closed cleanly

            start_line, headers = parse_head(head)
            method, target, version = parse_request_line(start_line)

            if not self._allow(peer_ip):
                self.stats.blocked += 1
                raise ProxyError(429, "Too Many Requests")

            self._check_auth(headers)

            self.stats.requests += 1
            started = time.monotonic()

            if method == "CONNECT":
                await self._handle_connect(reader, writer, conn_id, peer_ip, target)
                return  # the tunnel owns the socket from here on

            keep_alive = await self._handle_http(
                reader, writer, conn_id, peer_ip, method, target, version, headers, started
            )
            if not keep_alive:
                return

    # ------------------------------------------------------------------ #
    #  CONNECT tunnelling
    # ------------------------------------------------------------------ #

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: str,
        peer_ip: str,
        target: str,
    ) -> None:
        host, port = split_authority(target, 443)
        if not host:
            raise ProxyError(400, "Bad CONNECT target")
        host = to_ascii_host(host)

        if self.cfg.block_private and await is_private_host(host):
            raise ProxyError(403, "Forbidden: private address")

        up_reader, up_writer = await self._dial(host, port, tls=False)
        self.stats.tunnels += 1
        self.stats.status_counts["200"] += 1
        LOG.info("[%s] CONNECT %s:%d established", conn_id, host, port)

        writer.write(
            b"HTTP/1.1 200 Connection Established" + CRLF
            + b"Proxy-Agent: " + f"{SERVER_NAME}/{SERVER_VERSION}".encode() + CRLF
            + CRLF
        )
        await writer.drain()

        try:
            await self._tunnel(reader, writer, up_reader, up_writer)
        finally:
            self._kill(up_reader, up_writer)
            LOG.info("[%s] CONNECT %s:%d closed", conn_id, host, port)

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(CHUNK_SIZE)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (OSError, asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    if dst.can_write_eof():
                        dst.write_eof()

        t1 = asyncio.create_task(pump(client_reader, up_writer))
        t2 = asyncio.create_task(pump(up_reader, client_writer))
        try:
            await asyncio.gather(t1, t2, return_exceptions=True)
        finally:
            for task in (t1, t2):
                task.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)

    # ------------------------------------------------------------------ #
    #  Plain HTTP forwarding
    # ------------------------------------------------------------------ #

    def _resolve_target(
        self, target: str, headers: Headers
    ) -> Tuple[str, int, bool, str]:
        if target.startswith("//"):
            target = "http:" + target

        if "://" in target:
            parts = urlsplit(target)
            scheme = (parts.scheme or "http").lower()
            if scheme not in ("http", "https"):
                raise ProxyError(400, f"Unsupported scheme: {scheme}")
            host = parts.hostname
            if not host:
                raise ProxyError(400, "Missing host in request target")
            tls = scheme == "https"
            port = parts.port or (443 if tls else 80)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            return host, port, tls, path

        # origin-form: require a Host header
        host_header = headers.get("host")
        if not host_header:
            raise ProxyError(400, "Missing Host header")
        host, port = split_authority(host_header, 80)
        return host, port, False, target or "/"

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_id: str,
        peer_ip: str,
        method: str,
        target: str,
        version: str,
        headers: Headers,
        started: float,
    ) -> bool:
        host, port, tls, path = self._resolve_target(target, headers)
        host = to_ascii_host(host)

        if self.cfg.block_private and await is_private_host(host):
            raise ProxyError(403, "Forbidden: private address")

        authority = format_authority(host, port, tls)

        # ---- 100-continue: answer the client ourselves and drop the header --
        expect = headers.get("expect")
        if expect and "100-continue" in expect.lower():
            writer.write(b"HTTP/1.1 100 Continue" + CRLF + CRLF)
            await writer.drain()

        # ---- build the upstream request headers ---------------------------- #
        req_conn_tokens = headers.connection_tokens()
        upgrade_value = headers.get("upgrade")
        is_upgrade = bool(upgrade_value) and "upgrade" in req_conn_tokens

        out_headers = Headers()
        for name, value in headers:
            if name in ("proxy-authorization", "proxy-connection", "expect"):
                continue
            if is_upgrade and name in ("connection", "upgrade"):
                out_headers.add(name, value)
                continue
            if name in HOP_BY_HOP or name in req_conn_tokens:
                continue
            out_headers.add(name, value)

        prior_xff = headers.get("x-forwarded-for")
        out_headers.set(
            "Host", authority
        )
        out_headers.set(
            "X-Forwarded-For", f"{prior_xff}, {peer_ip}" if prior_xff else peer_ip
        )
        out_headers.set("X-Forwarded-Proto", "https" if tls else "http")
        out_headers.set("X-Forwarded-Host", authority)
        out_headers.set("Via", f"1.1 {SERVER_NAME}")
        out_headers.set("X-Request-Id", conn_id)

        # ---- request body framing ------------------------------------------ #
        te = headers.get("transfer-encoding")
        cl = headers.get("content-length")
        body_mode, body_len = "none", 0
        if te and "chunked" in te.lower():
            body_mode = "chunked"
        elif cl is not None:
            try:
                body_len = int(cl.strip())
            except ValueError:
                raise ProxyError(400, "Invalid Content-Length") from None
            if body_len < 0:
                raise ProxyError(400, "Invalid Content-Length")
            if body_len > 0:
                body_mode = "length"

        if body_mode == "chunked":
            out_headers.set("Transfer-Encoding", "chunked")
            out_headers.remove("Content-Length")
        elif cl is not None:
            out_headers.set("Content-Length", str(body_len))

        request_head = (
            f"{method} {path} HTTP/1.1\r\n".encode("latin-1", "replace")
            + out_headers.to_bytes()
        )

        key = (host, port, tls)

        # ---- connect (reusing a pooled socket when possible) --------------- #
        body_task: Optional[asyncio.Task] = None
        up_reader: Optional[asyncio.StreamReader] = None
        up_writer: Optional[asyncio.StreamWriter] = None
        resp_head: Optional[bytes] = None

        for attempt in (0, 1):
            from_pool = False
            if attempt == 0:
                pooled = self._pool_get(key)
                if pooled is not None:
                    up_reader, up_writer = pooled
                    from_pool = True
            if up_reader is None:
                up_reader, up_writer = await self._dial(host, port, tls)

            try:
                up_writer.write(request_head)
                await up_writer.drain()

                if body_mode != "none":
                    body_task = asyncio.create_task(
                        self._send_request_body(reader, up_writer, body_mode, body_len)
                    )

                resp_head = await asyncio.wait_for(
                    read_head(up_reader, self.cfg.max_header_bytes), self.cfg.read_timeout
                )
                if resp_head is None:
                    raise ConnectionError("upstream closed before sending a response")
                break
            except (
                OSError,
                ConnectionError,
                asyncio.IncompleteReadError,
                asyncio.TimeoutError,
            ) as exc:
                if body_task is not None:
                    body_task.cancel()
                    await asyncio.gather(body_task, return_exceptions=True)
                    body_task = None
                self._kill(up_reader, up_writer)
                up_reader = up_writer = None
                if attempt == 0 and from_pool and body_mode == "none":
                    LOG.debug("[%s] stale pooled connection, retrying", conn_id)
                    continue
                raise ProxyError(502, f"Upstream connection failed: {exc}") from exc

        assert up_reader is not None and up_writer is not None and resp_head is not None

        # ---- interim 1xx responses (e.g. 103 Early Hints) ------------------- #
        status_line, resp_headers = parse_head(resp_head)
        _, status, _reason = parse_status_line(status_line)
        while 100 <= status < 200 and status != 101:
            writer.write(resp_head)
            await writer.drain()
            resp_head = await asyncio.wait_for(
                read_head(up_reader, self.cfg.max_header_bytes), self.cfg.read_timeout
            )
            if resp_head is None:
                raise ProxyError(502, "Upstream closed after interim response")
            status_line, resp_headers = parse_head(resp_head)
            _, status, _reason = parse_status_line(status_line)

        resp_conn_tokens = resp_headers.connection_tokens()

        # ---- 101 Switching Protocols -> raw tunnel -------------------------- #
        if status == 101:
            writer.write(resp_head)
            await writer.drain()
            self.stats.status_counts["101"] += 1
            LOG.info("[%s] %s %s -> 101 switching protocols", conn_id, method, target[:100])
            try:
                await self._tunnel(reader, writer, up_reader, up_writer)
            finally:
                self._kill(up_reader, up_writer)
                if body_task is not None:
                    body_task.cancel()
                    await asyncio.gather(body_task, return_exceptions=True)
            return False

        # ---- response body framing ------------------------------------------ #
        resp_len = 0
        if method == "HEAD" or status in (204, 304):
            resp_mode = "none"
        else:
            rte = resp_headers.get("transfer-encoding")
            rcl = resp_headers.get("content-length")
            if rte and "chunked" in rte.lower():
                resp_mode = "chunked"
            elif rcl is not None:
                try:
                    resp_len = int(rcl.strip())
                except ValueError:
                    resp_mode = "close"
                else:
                    resp_mode = "length"
            else:
                resp_mode = "close"

        # ---- client keep-alive decision ------------------------------------- #
        if version == "HTTP/1.1":
            client_keep = "close" not in req_conn_tokens
        else:
            client_keep = "keep-alive" in req_conn_tokens
        keep = client_keep and resp_mode != "close" and not writer.is_closing()

        # ---- build the client-facing response head --------------------------- #
        client_headers = Headers()
        for name, value in resp_headers:
            if name in HOP_BY_HOP or name in resp_conn_tokens:
                continue
            client_headers.add(name, value)

        if resp_mode == "chunked":
            client_headers.set("Transfer-Encoding", "chunked")
            client_headers.remove("Content-Length")
        elif resp_mode == "length":
            client_headers.set("Content-Length", str(resp_len))
        else:
            client_headers.remove("Content-Length")

        client_headers.set("Connection", "keep-alive" if keep else "close")
        client_headers.set("Via", f"1.1 {SERVER_NAME}")

        writer.write(
            f"HTTP/1.1 {status} {reason_phrase(status)}\r\n".encode("latin-1")
            + client_headers.to_bytes()
        )
        await writer.drain()

        # ---- stream the response body ---------------------------------------- #
        body_ok = True
        try:
            sent = await relay_body(up_reader, writer, resp_mode, resp_len)
            self.stats.bytes_out += sent
        except (OSError, ConnectionError, asyncio.IncompleteReadError, ValueError):
            body_ok = False
            keep = False
            raise
        finally:
            if body_task is not None:
                if body_task.done():
                    with contextlib.suppress(Exception):
                        body_task.result()
                else:
                    body_task.cancel()
                    await asyncio.gather(body_task, return_exceptions=True)

        self.stats.status_counts[str(status)] += 1
        elapsed_ms = (time.monotonic() - started) * 1000.0
        LOG.info(
            "[%s] %s %s -> %d (%.1f ms)%s",
            conn_id,
            method,
            target[:100],
            status,
            elapsed_ms,
            "" if keep else " [closing]",
        )

        # ---- return the upstream socket to the pool -------------------------- #
        reusable = (
            body_ok
            and resp_mode in ("none", "length", "chunked")
            and "close" not in resp_conn_tokens
            and not up_writer.is_closing()
            and not up_reader.at_eof()
            and (body_task is None or body_task.done())
        )
        if reusable:
            self._pool_put(key, up_reader, up_writer)
        else:
            self._kill(up_reader, up_writer)

        return keep

    async def _send_request_body(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        mode: str,
        length: int,
    ) -> None:
        try:
            sent = await relay_body(reader, writer, mode, length)
            self.stats.bytes_in += sent
        except (OSError, ConnectionError, asyncio.IncompleteReadError, ValueError):
            raise

    # ------------------------------------------------------------------ #
    #  Connection plumbing
    # ------------------------------------------------------------------ #

    async def _dial(
        self, host: str, port: int, tls: bool
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=self.ssl_ctx if tls else None,
                    server_hostname=host if tls else None,
                    happy_eyeballs_delay=0.25,
                    limit=self.cfg.max_header_bytes,
                ),
                timeout=self.cfg.connect_timeout,
            )
        except asyncio.TimeoutError:
            raise ProxyError(504, f"Timed out connecting to {host}:{port}") from None
        except ssl.SSLError as exc:
            raise ProxyError(502, f"TLS handshake failed with {host}:{port}: {exc}") from exc
        except OSError as exc:
            raise ProxyError(502, f"Cannot connect to {host}:{port}: {exc}") from exc

        sock = writer.get_extra_info("socket")
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return reader, writer

    @staticmethod
    def _kill(
        reader: Optional[asyncio.StreamReader],
        writer: Optional[asyncio.StreamWriter],
    ) -> None:
        if writer is None:
            return
        with contextlib.suppress(Exception):
            writer.close()

    @staticmethod
    def _is_alive(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """Whether a pooled upstream connection is still clean enough to reuse."""
        if reader.at_eof() or writer.is_closing():
            return False
        sock = writer.get_extra_info("socket")
        if sock is None:
            return False
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            return False
        if not readable:
            return True
        # Readable: either EOF or unsolicited bytes. Either way, not reusable.
        return False

    def _pool_get(
        self, key
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        bucket = self.pool.get(key)
        if not bucket:
            return None
        now = time.monotonic()
        while bucket:
            ts, reader, writer = bucket.pop()
            if now - ts > self.cfg.upstream_idle_timeout:
                self._kill(reader, writer)
                continue
            if not self._is_alive(reader, writer):
                self._kill(reader, writer)
                continue
            return reader, writer
        return None

    def _pool_put(
        self,
        key,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        bucket = self.pool[key]
        if len(bucket) >= self.cfg.pool_size:
            self._kill(reader, writer)
            return
        bucket.append((time.monotonic(), reader, writer))

    @staticmethod
    async def _safe_write(writer: asyncio.StreamWriter, payload: bytes) -> None:
        with contextlib.suppress(Exception):
            writer.write(payload)
            await writer.drain()

    # ------------------------------------------------------------------ #
    #  Admin endpoint
    # ------------------------------------------------------------------ #

    async def handle_admin(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(HEADER_END), 5.0)
        except Exception:
            writer.close()
            return

        request_line = head.split(CRLF, 1)[0].decode("latin-1", "replace")
        parts = request_line.split()
        path = parts[1].split("?")[0] if len(parts) > 1 else "/"

        if path in ("/healthz", "/health"):
            status, ctype, body = 200, "application/json", b'{"status":"ok"}'
        elif path == "/stats":
            status = 200
            ctype = "application/json"
            body = json.dumps(self.stats.snapshot(), indent=2).encode()
        elif path == "/metrics":
            status = 200
            ctype = "text/plain; version=0.0.4"
            body = self._prometheus().encode()
        else:
            status, ctype, body = 404, "text/plain", b"not found\n"

        writer.write(
            f"HTTP/1.1 {status} {reason_phrase(status)}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"Server: {SERVER_NAME}/{SERVER_VERSION}\r\n"
            f"\r\n".encode("latin-1")
            + body
        )
        with contextlib.suppress(Exception):
            await writer.drain()
            writer.close()
            await writer.wait_closed()

    def _prometheus(self) -> str:
        s = self.stats.snapshot()
        lines = [
            "# HELP hyperproxy_uptime_seconds Time since the proxy started.",
            "# TYPE hyperproxy_uptime_seconds gauge",
            f"hyperproxy_uptime_seconds {s['uptime_seconds']}",
            "# HELP hyperproxy_connections_total Total accepted client connections.",
            "# TYPE hyperproxy_connections_total counter",
            f"hyperproxy_connections_total {s['total_connections']}",
            "# HELP hyperproxy_active_connections Currently open client connections.",
            "# TYPE hyperproxy_active_connections gauge",
            f"hyperproxy_active_connections {s['active_connections']}",
            "# HELP hyperproxy_requests_total Total proxied requests.",
            "# TYPE hyperproxy_requests_total counter",
            f"hyperproxy_requests_total {s['requests']}",
            "# HELP hyperproxy_tunnels_total Total CONNECT tunnels established.",
            "# TYPE hyperproxy_tunnels_total counter",
            f"hyperproxy_tunnels_total {s['tunnels']}",
            "# HELP hyperproxy_errors_total Total proxy errors.",
            "# TYPE hyperproxy_errors_total counter",
            f"hyperproxy_errors_total {s['errors']}",
            "# HELP hyperproxy_bytes_in_total Bytes received from clients.",
            "# TYPE hyperproxy_bytes_in_total counter",
            f"hyperproxy_bytes_in_total {s['bytes_in']}",
            "# HELP hyperproxy_bytes_out_total Bytes sent to clients.",
            "# TYPE hyperproxy_bytes_out_total counter",
            f"hyperproxy_bytes_out_total {s['bytes_out']}",
            "# HELP hyperproxy_responses_total Responses by status code.",
            "# TYPE hyperproxy_responses_total counter",
        ]
        for code, count in s["status_counts"].items():
            lines.append(f'hyperproxy_responses_total{{code="{code}"}} {count}')
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
#  Canned error responses
# --------------------------------------------------------------------------- #


def error_response(status: int, message: str) -> bytes:
    body = f"{status} {reason_phrase(status)}\n{message}\n".encode("utf-8")
    extra = ""
    if status == 407:
        extra = f'Proxy-Authenticate: Basic realm="{SERVER_NAME}"\r\n'
    head = (
        f"HTTP/1.1 {status} {reason_phrase(status)}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{extra}"
        f"Connection: close\r\n"
        f"Via: 1.1 {SERVER_NAME}\r\n"
        f"\r\n"
    ).encode("latin-1")
    return head + body


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hyperproxy",
        description="A dependency-free asyncio HTTP/1.1 forward proxy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--host",
        default=os.environ.get("PROXY_HOST", "0.0.0.0"),
        help="Address to bind the proxy listener to.",
    )
    p.add_argument(
        "-p",
        "--port",
        type=int,
        default=int(os.environ.get("PROXY_PORT", "8080")),
        help="Proxy listener port.",
    )
    p.add_argument(
        "--admin-port",
        type=int,
        default=int(os.environ.get("PROXY_ADMIN_PORT", "0")) or None,
        help="Port for /healthz, /stats and /metrics (0 disables).",
    )
    p.add_argument(
        "--user",
        default=os.environ.get("PROXY_USER"),
        help="Username for Basic proxy authentication (optional).",
    )
    p.add_argument(
        "--password",
        default=os.environ.get("PROXY_PASSWORD"),
        help="Password for Basic proxy authentication (optional).",
    )
    p.add_argument(
        "--rate-limit",
        type=float,
        default=float(os.environ.get("PROXY_RATE_LIMIT", "0")),
        help="Requests per second per client IP (0 disables).",
    )
    p.add_argument(
        "--rate-burst",
        type=float,
        default=float(os.environ.get("PROXY_RATE_BURST", "0")),
        help="Token bucket burst size (defaults to the rate limit).",
    )
    p.add_argument(
        "--max-header-bytes",
        type=int,
        default=65536,
        help="Maximum size of a request header block.",
    )
    p.add_argument(
        "--connect-timeout",
        type=float,
        default=15.0,
        help="Seconds to wait for an upstream TCP/TLS connection.",
    )
    p.add_argument(
        "--read-timeout",
        type=float,
        default=60.0,
        help="Seconds to wait for upstream response headers.",
    )
    p.add_argument(
        "--idle-timeout",
        type=float,
        default=120.0,
        help="Seconds a client connection may stay idle between requests.",
    )
    p.add_argument(
        "--upstream-idle-timeout",
        type=float,
        default=30.0,
        help="Seconds an idle pooled upstream connection is kept.",
    )
    p.add_argument(
        "--pool-size",
        type=int,
        default=8,
        help="Maximum pooled idle connections per origin.",
    )
    p.add_argument(
        "--block-private",
        action="store_true",
        help="Refuse to connect to private/loopback/link-local addresses.",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )
    p.add_argument(
        "--version", action="version", version=f"{SERVER_NAME} {SERVER_VERSION}"
    )
    return p


async def amain(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)

    cfg = Config(
        host=args.host,
        port=args.port,
        admin_port=args.admin_port,
        username=args.user,
        password=args.password,
        max_header_bytes=args.max_header_bytes,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        idle_timeout=args.idle_timeout,
        upstream_idle_timeout=args.upstream_idle_timeout,
        pool_size=args.pool_size,
        rate_limit=args.rate_limit,
        rate_burst=args.rate_burst,
        block_private=args.block_private,
        verbose=args.verbose,
    )

    if cfg.username and not cfg.password:
        LOG.warning("--user given without --password; the password will be empty")

    proxy = HyperProxy(cfg)
    await proxy.start()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop(*_args) -> None:
        if not stop_event.is_set():
            LOG.info("received shutdown signal")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _request_stop)

    try:
        await stop_event.wait()
    finally:
        await proxy.stop()
    return 0


def main() -> None:
    try:
        raise SystemExit(asyncio.run(amain()))
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == "__main__":
    main()