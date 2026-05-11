"""
Local HTTP proxy server.

Intercepts the user's browser traffic and forwards everything through
the Apps Script relay (MITM-decrypts HTTPS locally, forwards requests
as JSON to script.google.com fronted through www.google.com).
"""

import asyncio
import logging
import re
import socket
import ssl
import time
import ipaddress
from urllib.parse import urlparse

try:
    import certifi
except Exception:  # optional dependency fallback
    certifi = None

from constants import (
    CACHE_MAX_MB,
    CACHE_TTL_MAX,
    CACHE_TTL_STATIC_LONG,
    CACHE_TTL_STATIC_MED,
    CLIENT_IDLE_TIMEOUT,
    GOOGLE_DIRECT_ALLOW_EXACT,
    GOOGLE_DIRECT_ALLOW_SUFFIXES,
    GOOGLE_DIRECT_EXACT_EXCLUDE,
    GOOGLE_DIRECT_SUFFIX_EXCLUDE,
    GOOGLE_OWNED_EXACT,
    GOOGLE_OWNED_SUFFIXES,
    LARGE_FILE_EXTS,
    MAX_HEADER_BYTES,
    MAX_REQUEST_BODY_BYTES,
    SNI_REWRITE_SUFFIXES,
    STATIC_EXTS,
    TCP_CONNECT_TIMEOUT,
    TRACE_HOST_SUFFIXES,
    UNCACHEABLE_HEADER_NAMES,
)
from domain_fronter import DomainFronter

log = logging.getLogger("Proxy")


def _is_ip_literal(host: str) -> bool:
    """True for IPv4/IPv6 literals (strips brackets around IPv6)."""
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _parse_content_length(header_block: bytes) -> int:
    """Return Content-Length or 0. Matches only the exact header name."""
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def _has_unsupported_transfer_encoding(header_block: bytes) -> bool:
    """True when the request uses Transfer-Encoding, which we don't stream."""
    for raw_line in header_block.split(b"\r\n"):
        name, sep, value = raw_line.partition(b":")
        if not sep:
            continue
        if name.strip().lower() != b"transfer-encoding":
            continue
        encodings = [
            token.strip().lower()
            for token in value.decode(errors="replace").split(",")
            if token.strip()
        ]
        return any(token != "identity" for token in encodings)
    return False


class ResponseCache:
    """Simple LRU response cache — avoids repeated relay calls."""

    def __init__(self, max_mb: int = 50):
        self._store: dict[str, tuple[bytes, float]] = {}
        self._size = 0
        self._max = max_mb * 1024 * 1024
        self.hits = 0
        self.misses = 0

    def get(self, url: str) -> bytes | None:
        entry = self._store.get(url)
        if not entry:
            self.misses += 1
            return None
        raw, expires = entry
        if time.time() > expires:
            self._size -= len(raw)
            del self._store[url]
            self.misses += 1
            return None
        self.hits += 1
        return raw

    def put(self, url: str, raw_response: bytes, ttl: int = 300):
        size = len(raw_response)
        if size > self._max // 4 or size == 0:
            return
        # Evict oldest to make room
        while self._size + size > self._max and self._store:
            oldest = next(iter(self._store))
            self._size -= len(self._store[oldest][0])
            del self._store[oldest]
        if url in self._store:
            self._size -= len(self._store[url][0])
        self._store[url] = (raw_response, time.time() + ttl)
        self._size += size

    @staticmethod
    def parse_ttl(raw_response: bytes, url: str) -> int:
        """Determine cache TTL from response headers and URL."""
        hdr_end = raw_response.find(b"\r\n\r\n")
        if hdr_end < 0:
            return 0
        hdr = raw_response[:hdr_end].decode(errors="replace").lower()

        # Don't cache errors or non-200
        if b"HTTP/1.1 200" not in raw_response[:20]:
            return 0
        if "no-store" in hdr or "private" in hdr or "set-cookie:" in hdr:
            return 0

        # Explicit max-age
        m = re.search(r"max-age=(\d+)", hdr)
        if m:
            return min(int(m.group(1)), CACHE_TTL_MAX)

        # Heuristic by content type / extension
        path = url.split("?")[0].lower()
        for ext in STATIC_EXTS:
            if path.endswith(ext):
                return CACHE_TTL_STATIC_LONG

        ct_m = re.search(r"content-type:\s*([^\r\n]+)", hdr)
        ct = ct_m.group(1) if ct_m else ""
        if "image/" in ct or "font/" in ct:
            return CACHE_TTL_STATIC_LONG
        if "text/css" in ct or "javascript" in ct:
            return CACHE_TTL_STATIC_MED
        if "text/html" in ct or "application/json" in ct:
            return 0  # don't cache dynamic content by default

        return 0


class ProxyServer:
    # Pulled from constants.py so users can override any subset via config.
    _GOOGLE_DIRECT_EXACT_EXCLUDE  = GOOGLE_DIRECT_EXACT_EXCLUDE
    _GOOGLE_DIRECT_SUFFIX_EXCLUDE = GOOGLE_DIRECT_SUFFIX_EXCLUDE
    _GOOGLE_DIRECT_ALLOW_EXACT    = GOOGLE_DIRECT_ALLOW_EXACT
    _GOOGLE_DIRECT_ALLOW_SUFFIXES = GOOGLE_DIRECT_ALLOW_SUFFIXES
    _TRACE_HOST_SUFFIXES          = TRACE_HOST_SUFFIXES
    _DOWNLOAD_DEFAULT_EXTS        = tuple(sorted(LARGE_FILE_EXTS))
    _DOWNLOAD_ACCEPT_MARKERS      = (
        "application/octet-stream",
        "application/zip",
        "application/x-bittorrent",
        "video/",
        "audio/",
    )

    def __init__(self, config: dict):
        self.host = config.get("listen_host", "127.0.0.1")
        self.port = config.get("listen_port", 8080)
        self.socks_enabled = config.get("socks5_enabled", True)
        self.socks_host = config.get("socks5_host", self.host)
        self.socks_port = config.get("socks5_port", 1080)
        if self.socks_enabled and self.socks_host == self.host \
                and int(self.socks_port) == int(self.port):
            raise ValueError(
                f"listen_port and socks5_port must differ on the same host "
                f"(both set to {self.port} on {self.host}). "
                f"Change one of them in config.json."
            )
        self.fronter = DomainFronter(config)
        self.mitm = None
        self._cache = ResponseCache(max_mb=CACHE_MAX_MB)
        self._direct_fail_until: dict[str, float] = {}
        self._servers: list[asyncio.base_events.Server] = []
        self._client_tasks: set[asyncio.Task] = set()
        self._tcp_connect_timeout = self._cfg_float(
            config, "tcp_connect_timeout", TCP_CONNECT_TIMEOUT, minimum=1.0,
        )
        self._download_min_size = self._cfg_int(
            config, "chunked_download_min_size", 5 * 1024 * 1024, minimum=0,
        )
        self._download_chunk_size = self._cfg_int(
            config, "chunked_download_chunk_size", 512 * 1024, minimum=64 * 1024,
        )
        self._download_max_parallel = self._cfg_int(
            config, "chunked_download_max_parallel", 8, minimum=1,
        )
        self._download_max_chunks = self._cfg_int(
            config, "chunked_download_max_chunks", 256, minimum=1,
        )
        self._download_extensions, self._download_any_extension = (
            self._normalize_download_extensions(
                config.get(
                    "chunked_download_extensions",
                    list(self._DOWNLOAD_DEFAULT_EXTS),
                )
            )
        )

        # hosts override — DNS fake-map: domain/suffix → IP
        # Checked before any real DNS lookup; supports exact and suffix matching.
        self._hosts: dict[str, str] = config.get("hosts", {})
        configured_direct_exclude = config.get("direct_google_exclude", [])
        self._direct_google_exclude = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_EXACT_EXCLUDE) +
                list(configured_direct_exclude)
            )
        }
        configured_direct_allow = config.get("direct_google_allow", [])
        self._direct_google_allow = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_ALLOW_EXACT) +
                list(configured_direct_allow)
            )
        }

        # ── Per-host policy ────────────────────────────────────────
        # block_hosts  — refuse traffic entirely (close or 403)
        # bypass_hosts — route directly (no MITM, no relay)
        # Both accept exact hostnames and leading-dot suffix patterns,
        # e.g. ".local" matches any *.local domain.
        self._block_hosts  = self._load_host_rules(config.get("block_hosts", []))
        self._bypass_hosts = self._load_host_rules(config.get("bypass_hosts", []))

        # Route YouTube through the relay when requested; the Google frontend
        # IP can enforce SafeSearch on the SNI-rewrite path.
        if config.get("youtube_via_relay", False):
            self._SNI_REWRITE_SUFFIXES = tuple(
                s for s in SNI_REWRITE_SUFFIXES
                if s not in self._YOUTUBE_SNI_SUFFIXES
            )
            log.info("youtube_via_relay enabled — YouTube routed through relay")
        else:
            self._SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

        try:
            from mitm import MITMCertManager
            self.mitm = MITMCertManager()
        except ImportError:
            log.error("Apps Script relay requires the 'cryptography' package.")
            log.error("Run: pip install cryptography")
            raise SystemExit(1)

    # ── Host-policy helpers ───────────────────────────────────────

    @staticmethod
    def _cfg_int(config: dict, key: str, default: int, *, minimum: int = 1) -> int:
        try:
            value = int(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @staticmethod
    def _cfg_float(config: dict, key: str, default: float,
                   *, minimum: float = 0.1) -> float:
        try:
            value = float(config.get(key, default))
        except (TypeError, ValueError):
            value = default
        return max(minimum, value)

    @classmethod
    def _normalize_download_extensions(cls, raw) -> tuple[tuple[str, ...], bool]:
        values = raw if isinstance(raw, (list, tuple)) else cls._DOWNLOAD_DEFAULT_EXTS
        normalized: list[str] = []
        any_extension = False
        seen: set[str] = set()
        for item in values:
            ext = str(item).strip().lower()
            if not ext:
                continue
            if ext in {"*", ".*"}:
                any_extension = True
                continue
            if not ext.startswith("."):
                ext = "." + ext
            if ext not in seen:
                seen.add(ext)
                normalized.append(ext)
        if not normalized and not any_extension:
            normalized = list(cls._DOWNLOAD_DEFAULT_EXTS)
        return tuple(normalized), any_extension

    def update_config(self, new_cfg: dict) -> list[str]:
        changed: list[str] = []

        new_hosts = dict(new_cfg.get("hosts", {}) or {})
        if new_hosts != self._hosts:
            self._hosts = new_hosts
            changed.append("hosts")

        new_excl = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_EXACT_EXCLUDE) +
                list(new_cfg.get("direct_google_exclude", []))
            )
        }
        if new_excl != self._direct_google_exclude:
            self._direct_google_exclude = new_excl
            changed.append("direct_google_exclude")

        new_allow = {
            h.lower().rstrip(".")
            for h in (
                list(self._GOOGLE_DIRECT_ALLOW_EXACT) +
                list(new_cfg.get("direct_google_allow", []))
            )
        }
        if new_allow != self._direct_google_allow:
            self._direct_google_allow = new_allow
            changed.append("direct_google_allow")

        new_block = self._load_host_rules(new_cfg.get("block_hosts", []))
        if new_block != self._block_hosts:
            self._block_hosts = new_block
            changed.append("block_hosts")
        new_bypass = self._load_host_rules(new_cfg.get("bypass_hosts", []))
        if new_bypass != self._bypass_hosts:
            self._bypass_hosts = new_bypass
            changed.append("bypass_hosts")

        if new_cfg.get("youtube_via_relay", False):
            new_sni_rewrite = tuple(
                s for s in SNI_REWRITE_SUFFIXES
                if s not in self._YOUTUBE_SNI_SUFFIXES
            )
        else:
            new_sni_rewrite = SNI_REWRITE_SUFFIXES
        if new_sni_rewrite != self._SNI_REWRITE_SUFFIXES:
            self._SNI_REWRITE_SUFFIXES = new_sni_rewrite
            changed.append("youtube_via_relay")

        new_tcp = self._cfg_float(
            new_cfg, "tcp_connect_timeout", TCP_CONNECT_TIMEOUT, minimum=1.0,
        )
        if new_tcp != self._tcp_connect_timeout:
            self._tcp_connect_timeout = new_tcp
            changed.append("tcp_connect_timeout")

        new_min = self._cfg_int(
            new_cfg, "chunked_download_min_size", 5 * 1024 * 1024, minimum=0,
        )
        if new_min != self._download_min_size:
            self._download_min_size = new_min
            changed.append("chunked_download_min_size")

        new_chunk = self._cfg_int(
            new_cfg, "chunked_download_chunk_size", 512 * 1024, minimum=64 * 1024,
        )
        if new_chunk != self._download_chunk_size:
            self._download_chunk_size = new_chunk
            changed.append("chunked_download_chunk_size")

        new_par = self._cfg_int(
            new_cfg, "chunked_download_max_parallel", 8, minimum=1,
        )
        if new_par != self._download_max_parallel:
            self._download_max_parallel = new_par
            changed.append("chunked_download_max_parallel")

        new_maxc = self._cfg_int(
            new_cfg, "chunked_download_max_chunks", 256, minimum=1,
        )
        if new_maxc != self._download_max_chunks:
            self._download_max_chunks = new_maxc
            changed.append("chunked_download_max_chunks")

        new_exts = self._normalize_download_extensions(
            new_cfg.get("chunked_download_extensions", list(self._DOWNLOAD_DEFAULT_EXTS))
        )
        if new_exts != (self._download_extensions, self._download_any_extension):
            self._download_extensions, self._download_any_extension = new_exts
            changed.append("chunked_download_extensions")

        return changed

    def _track_current_task(self) -> asyncio.Task | None:
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        return task

    def _untrack_task(self, task: asyncio.Task | None) -> None:
        if task is not None:
            self._client_tasks.discard(task)

    @staticmethod
    def _load_host_rules(raw) -> tuple[set[str], tuple[str, ...]]:
        """Accept a list of host strings; return (exact_set, suffix_tuple).

        A rule starting with '.' (e.g. ".internal") is a suffix rule.
        Everything else is treated as an exact match. Case-insensitive.
        """
        exact: set[str] = set()
        suffixes: list[str] = []
        for item in raw or []:
            h = str(item).strip().lower().rstrip(".")
            if not h:
                continue
            if h.startswith("."):
                suffixes.append(h)
            else:
                exact.add(h)
        return exact, tuple(suffixes)

    @staticmethod
    def _host_matches_rules(host: str,
                            rules: tuple[set[str], tuple[str, ...]]) -> bool:
        exact, suffixes = rules
        h = host.lower().rstrip(".")
        if h in exact:
            return True
        for s in suffixes:
            if h.endswith(s):
                return True
        return False

    def _is_blocked(self, host: str) -> bool:
        return self._host_matches_rules(host, self._block_hosts)

    def _is_bypassed(self, host: str) -> bool:
        return self._host_matches_rules(host, self._bypass_hosts)

    @staticmethod
    def _header_value(headers: dict | None, name: str) -> str:
        if not headers:
            return ""
        for key, value in headers.items():
            if key.lower() == name:
                return str(value)
        return ""

    def _cache_allowed(self, method: str, url: str,
                       headers: dict | None, body: bytes) -> bool:
        if method.upper() != "GET" or body:
            return False
        for name in UNCACHEABLE_HEADER_NAMES:
            if self._header_value(headers, name):
                return False
        return self.fronter._is_static_asset_url(url)

    @classmethod
    def _should_trace_host(cls, host: str) -> bool:
        h = host.lower().rstrip(".")
        return any(
            token == h or token in h or h.endswith("." + token)
            for token in cls._TRACE_HOST_SUFFIXES
        )

    def _log_response_summary(self, url: str, response: bytes):
        status, headers, body = self.fronter._split_raw_response(response)
        host = (urlparse(url).hostname or "").lower()

        if status >= 300 or self._should_trace_host(host):
            location = headers.get("location", "") or "-"
            server = headers.get("server", "") or "-"
            cf_ray = headers.get("cf-ray", "") or "-"
            content_type = headers.get("content-type", "") or "-"
            body_len = len(body)

            body_hint = "-"
            rate_limited = False

            # Handle text-like responses (HTML, plain text, JSON…)
            if ("text" in content_type.lower() or "json" in content_type.lower()) and body:
                sample = body[:1200].decode(errors="replace").lower()

                # --- Structured HTML title extraction ---
                if "<title>" in sample and "</title>" in sample:
                    title = sample.split("<title>", 1)[1].split("</title>", 1)[0]
                    body_hint = title.strip()[:120] or "-"

                # --- Known content patterns ---
                elif "captcha" in sample:
                    body_hint = "captcha"
                elif "turnstile" in sample:
                    body_hint = "turnstile"
                elif "loading" in sample:
                    body_hint = "loading"

                # --- Rate-limit / quota markers ---
                rate_limit_markers = (
                    "too many",
                    "rate limit",
                    "quota",
                    "quota exceeded",
                    "request limit",
                    "دفعات زیاد",
                    "بیش از حد",
                    "سرویس در طول یک روز",
                )

                if any(m in sample for m in rate_limit_markers):
                    rate_limited = True
                    body_hint = "quota_exceeded"

            log_msg = (
                "RESP ← %s status=%s type=%s len=%s server=%s location=%s cf-ray=%s hint=%s"
            )
            log_args = (
                host or url[:60],
                status,
                content_type,
                body_len,
                server,
                location,
                cf_ray,
                body_hint,
            )

            if rate_limited:
                log.warning("RATE LIMIT detected! " + log_msg, *log_args)
            else:
                log.info(log_msg, *log_args)

    async def bind(self):
        http_srv = await asyncio.start_server(self._on_client, self.host, self.port)
        socks_srv = None
        if self.socks_enabled:
            try:
                socks_srv = await asyncio.start_server(
                    self._on_socks_client, self.socks_host, self.socks_port
                )
            except OSError as e:
                log.error("SOCKS5 listener failed on %s:%d: %s",
                          self.socks_host, self.socks_port, e)
        self._servers = [s for s in (http_srv, socks_srv) if s]
        log.info("HTTP proxy listening on %s:%d", self.host, self.port)
        if socks_srv:
            log.info(
                "SOCKS5 proxy listening on %s:%d",
                self.socks_host, self.socks_port,
            )

    async def serve(self):
        if not self._servers:
            return
        http_srv = self._servers[0]
        socks_srv = self._servers[1] if len(self._servers) > 1 else None
        try:
            async with http_srv:
                if socks_srv:
                    async with socks_srv:
                        await asyncio.gather(
                            http_srv.serve_forever(),
                            socks_srv.serve_forever(),
                        )
                else:
                    await http_srv.serve_forever()
        except asyncio.CancelledError:
            raise

    async def start(self):
        await self.bind()
        await self.serve()

    async def stop(self):
        """Shut down all listeners and release relay resources."""
        for srv in self._servers:
            try:
                srv.close()
            except Exception:
                pass
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        self._servers = []

        current = asyncio.current_task()
        client_tasks = [task for task in self._client_tasks if task is not current]
        for task in client_tasks:
            task.cancel()
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        self._client_tasks.clear()

        try:
            await self.fronter.close()
        except Exception as exc:
            log.debug("fronter.close: %s", exc)

    # ── client handler ────────────────────────────────────────────

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not first_line:
                return

            # Read remaining headers
            header_block = first_line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                header_block += line
                if len(header_block) > MAX_HEADER_BYTES:
                    log.warning("Request header block exceeds cap — closing")
                    return
                if line in (b"\r\n", b"\n", b""):
                    break

            if _has_unsupported_transfer_encoding(header_block):
                log.warning("Unsupported Transfer-Encoding on client request")
                writer.write(
                    b"HTTP/1.1 501 Not Implemented\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

            request_line = first_line.decode(errors="replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return

            method = parts[0].upper()

            if method == "CONNECT":
                await self._do_connect(parts[1], reader, writer)
            else:
                await self._do_http(header_block, reader, writer)

        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            log.debug("Timeout: %s", addr)
        except Exception as e:
            log.error("Error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _on_socks_client(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        task = self._track_current_task()
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                return

            methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10)
            if 0x00 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return

            writer.write(b"\x05\x00")
            await writer.drain()

            req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
            ver, cmd, _rsv, atyp = req
            if ver != 5 or cmd != 0x01:
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if atyp == 0x01:
                raw = await asyncio.wait_for(reader.readexactly(4), timeout=10)
                host = socket.inet_ntoa(raw)
            elif atyp == 0x03:
                ln = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
                host = (await asyncio.wait_for(reader.readexactly(ln), timeout=10)).decode(
                    errors="replace"
                )
            elif atyp == 0x04:
                raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            port_raw = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            port = int.from_bytes(port_raw, "big")

            log.info("SOCKS5 CONNECT → %s:%d", host, port)

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._handle_target_tunnel(host, port, reader, writer)

        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            log.debug("SOCKS5 timeout: %s", addr)
        except Exception as e:
            log.error("SOCKS5 error (%s): %s", addr, e)
        finally:
            self._untrack_task(task)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── CONNECT (HTTPS tunnelling) ────────────────────────────────

    async def _do_connect(self, target: str, reader, writer):
        host, _, port_str = target.rpartition(":")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            log.warning("CONNECT invalid target: %r", target)
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        if not host:
            host, port = target, 443

        log.info("CONNECT → %s:%d", host, port)

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._handle_target_tunnel(host, port, reader, writer)

    async def _handle_target_tunnel(self, host: str, port: int,
                                    reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter):
        """Route a target connection through the Apps Script relay."""
        # ── Block / bypass policy ─────────────────────────────────
        if self._is_blocked(host):
            log.warning("BLOCKED → %s:%d (matches block_hosts)", host, port)
            try:
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
            return

        if self._is_bypassed(host):
            log.info("Bypass tunnel → %s:%d (matches bypass_hosts)", host, port)
            await self._do_direct_tunnel(host, port, reader, writer)
            return

        # ── IP-literal destinations ───────────────────────────────
        # Prefer a direct tunnel first (works for unblocked IPs and keeps
        # TLS end-to-end). If the network blocks the route (common for
        # Telegram data-centers behind DPI), fall back to:
        #   • port 443 → MITM + relay through Apps Script
        #   • port 80  → plain-HTTP relay through Apps Script
        #   • other    → give up (non-HTTP; can't be relayed)
        # We use a shorter connect timeout for IP literals (4 s) because
        # when the route is DPI-dropped, waiting longer doesn't help and
        # clients like Telegram speed up DC-rotation when we fail fast.
        # We remember per-IP failures for a short while so subsequent
        # connects skip the doomed direct attempt.
        if _is_ip_literal(host):
            if not self._direct_temporarily_disabled(host):
                log.info("Direct tunnel → %s:%d (IP literal)", host, port)
                ok = await self._do_direct_tunnel(
                    host, port, reader, writer, timeout=4.0,
                )
                if ok:
                    return
                self._remember_direct_failure(host, ttl=300)
                if port not in (80, 443):
                    log.warning("Direct tunnel failed for %s:%d", host, port)
                    return
                log.warning(
                    "Direct tunnel fallback → %s:%d (switching to relay)",
                    host, port,
                )
            else:
                log.info(
                    "Relay fallback → %s:%d (direct temporarily disabled)",
                    host, port,
                )
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            elif port == 80:
                await self._do_plain_http_tunnel(host, port, reader, writer)
            return

        override_ip = self._sni_rewrite_ip(host)
        if override_ip:
            # SNI-blocked domain: MITM-decrypt from browser, then
            # re-connect to the override IP with SNI=front_domain so
            # the ISP never sees the blocked hostname in the TLS handshake.
            log.info("SNI-rewrite tunnel → %s via %s (SNI: %s)",
                     host, override_ip, self.fronter.sni_host)
            await self._do_sni_rewrite_tunnel(host, port, reader, writer,
                                              connect_ip=override_ip)
        elif self._is_google_domain(host):
            if self._direct_temporarily_disabled(host):
                log.info("Relay fallback → %s (direct tunnel temporarily disabled)", host)
                if port == 443:
                    await self._do_mitm_connect(host, port, reader, writer)
                else:
                    await self._do_plain_http_tunnel(host, port, reader, writer)
                return

            log.info("Direct tunnel → %s (Google domain, skipping relay)", host)
            ok = await self._do_direct_tunnel(host, port, reader, writer)
            if ok:
                return

            self._remember_direct_failure(host)
            log.warning("Direct tunnel fallback → %s (switching to relay)", host)
            if port == 443:
                await self._do_mitm_connect(host, port, reader, writer)
            else:
                await self._do_plain_http_tunnel(host, port, reader, writer)
        elif port == 443:
            await self._do_mitm_connect(host, port, reader, writer)
        elif port == 80:
            await self._do_plain_http_tunnel(host, port, reader, writer)
        else:
            # Non-HTTP port (e.g. mtalk:5228 XMPP, IMAP, SMTP, SSH) —
            # payload isn't HTTP, so we can't relay or MITM. Tunnel bytes.
            log.info("Direct tunnel → %s:%d (non-HTTP port)", host, port)
            ok = await self._do_direct_tunnel(host, port, reader, writer)
            if not ok:
                log.warning("Direct tunnel failed for %s:%d", host, port)

    # ── Hosts override (fake DNS) ─────────────────────────────────

    # Built-in list of domains that must be reached via Google's frontend IP
    # with SNI rewritten to `front_domain` (default: www.google.com).
    # Source: constants.SNI_REWRITE_SUFFIXES.
    # When youtube_via_relay is enabled the YouTube suffixes are removed so
    # YouTube goes through the Apps Script relay instead.
    _YOUTUBE_SNI_SUFFIXES = frozenset({
        "youtube.com", "youtu.be", "youtube-nocookie.com",
    })
    _SNI_REWRITE_SUFFIXES = SNI_REWRITE_SUFFIXES

    def _sni_rewrite_ip(self, host: str) -> str | None:
        """Return the IP to SNI-rewrite `host` through, or None.

        Order of precedence:
          1. Explicit entry in config `hosts` map (exact or suffix match).
          2. Built-in `_SNI_REWRITE_SUFFIXES` → mapped to config `google_ip`.
        """
        ip = self._hosts_ip(host)
        if ip:
            return ip
        h = host.lower().rstrip(".")
        for suffix in self._SNI_REWRITE_SUFFIXES:
            if h == suffix or h.endswith("." + suffix):
                return self.fronter.connect_host  # configured google_ip
        return None

    def _hosts_ip(self, host: str) -> str | None:
        """Return override IP for host if defined in config 'hosts', else None.

        Supports exact match and suffix match (e.g. 'youtube.com' matches
        'www.youtube.com', 'm.youtube.com', etc.).
        """
        h = host.lower().rstrip(".")
        if h in self._hosts:
            return self._hosts[h]
        # suffix match: check every parent label
        parts = h.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._hosts:
                return self._hosts[parent]
        return None

    # ── Google domain detection ───────────────────────────────────

    # Google-owned domains that may use the raw direct-tunnel shortcut.
    # YouTube/googlevideo SNIs are blocked; they go through
    # _do_sni_rewrite_tunnel via the hosts map instead.
    # Source: constants.GOOGLE_OWNED_SUFFIXES / GOOGLE_OWNED_EXACT.
    _GOOGLE_OWNED_SUFFIXES = GOOGLE_OWNED_SUFFIXES
    _GOOGLE_OWNED_EXACT = GOOGLE_OWNED_EXACT

    def _is_google_domain(self, host: str) -> bool:
        """Return True if host should use the raw direct Google shortcut."""
        h = host.lower().rstrip(".")
        if self._is_direct_google_excluded(h):
            return False
        if not self._is_google_owned_domain(h):
            return False
        return self._is_direct_google_allowed(h)

    def _is_google_owned_domain(self, host: str) -> bool:
        if host in self._GOOGLE_OWNED_EXACT:
            return True
        for suffix in self._GOOGLE_OWNED_SUFFIXES:
            if host.endswith(suffix):
                return True
        return False

    def _is_direct_google_excluded(self, host: str) -> bool:
        if host in self._direct_google_exclude:
            return True
        for suffix in self._GOOGLE_DIRECT_SUFFIX_EXCLUDE:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_exclude:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _is_direct_google_allowed(self, host: str) -> bool:
        if host in self._direct_google_allow:
            return True
        for suffix in self._GOOGLE_DIRECT_ALLOW_SUFFIXES:
            if host.endswith(suffix):
                return True
        for token in self._direct_google_allow:
            if token.startswith(".") and host.endswith(token):
                return True
        return False

    def _direct_temporarily_disabled(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        now = time.time()
        disabled = False
        for key in self._direct_failure_keys(h):
            until = self._direct_fail_until.get(key, 0)
            if until > now:
                disabled = True
            else:
                self._direct_fail_until.pop(key, None)
        return disabled

    def _remember_direct_failure(self, host: str, ttl: int = 600):
        until = time.time() + ttl
        for key in self._direct_failure_keys(host.lower().rstrip(".")):
            self._direct_fail_until[key] = until

    def _direct_failure_keys(self, host: str) -> tuple[str, ...]:
        keys = [host]
        if host.endswith(".google.com") or host == "google.com":
            keys.append("*.google.com")
        if host.endswith(".googleapis.com") or host == "googleapis.com":
            keys.append("*.googleapis.com")
        if host.endswith(".gstatic.com") or host == "gstatic.com":
            keys.append("*.gstatic.com")
        if host.endswith(".googleusercontent.com") or host == "googleusercontent.com":
            keys.append("*.googleusercontent.com")
        return tuple(dict.fromkeys(keys))

    async def _open_tcp_connection(self, target: str, port: int,
                                   timeout: float = 10.0):
        """Connect with IPv4-first resolution and clearer failure reporting."""
        errors: list[str] = []
        loop = asyncio.get_running_loop()

        # Strip IPv6 brackets (CONNECT may deliver "[::1]" as the hostname).
        # ipaddress.ip_address() rejects the bracketed form, which would
        # otherwise force a DNS lookup for an IP literal and fail.
        lookup_target = target.strip()
        if lookup_target.startswith("[") and lookup_target.endswith("]"):
            lookup_target = lookup_target[1:-1]

        try:
            ipaddress.ip_address(lookup_target)
            candidates = [(0, lookup_target)]
        except ValueError:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(
                        lookup_target,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=timeout,
                )
            except Exception as exc:
                raise OSError(f"dns lookup failed for {lookup_target}: {exc!r}") from exc

            candidates = []
            seen = set()
            for family, _type, _proto, _canon, sockaddr in infos:
                ip = sockaddr[0]
                key = (family, ip)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((family, ip))

            candidates.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)

        for family, ip in candidates:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(ip, port, family=family or 0),
                    timeout=timeout,
                )
            except Exception as exc:
                fam = "ipv4" if family == socket.AF_INET else (
                    "ipv6" if family == socket.AF_INET6 else "auto"
                )
                errors.append(f"{ip} ({fam}): {exc!r}")

        raise OSError("; ".join(errors) or f"connect failed for {target}:{port}")

    # ── Direct tunnel (no MITM) ───────────────────────────────────

    async def _do_direct_tunnel(self, host: str, port: int,
                                reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter,
                                connect_ip: str | None = None,
                                timeout: float | None = None):
        """Pipe raw TLS bytes directly to the target server.

        connect_ip overrides DNS: the TCP connection goes to that IP
        while the browser's TLS (SNI=host) is piped through unchanged.
        Without an override we connect to the real hostname so browser-safe
        Google properties (Gemini assets, Play, Accounts, etc.) use their
        normal edge instead of being forced onto the fronting IP.
        """
        target_ip = connect_ip or host
        effective_timeout = (
            self._tcp_connect_timeout if timeout is None else float(timeout)
        )
        try:
            r_remote, w_remote = await self._open_tcp_connection(
                target_ip, port, timeout=effective_timeout,
            )
        except Exception as e:
            log.error("Direct tunnel connect failed (%s via %s): %s",
                      host, target_ip, e)
            return False

        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as e:
                log.debug("Pipe %s ended: %s", label, e)
            finally:
                # Half-close rather than hard-close so the other direction
                # can still flush final bytes (important for TLS close_notify).
                try:
                    if not dst.is_closing() and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    try:
                        dst.close()
                    except Exception:
                        pass

        await asyncio.gather(
            pipe(reader, w_remote, f"client→{host}"),
            pipe(r_remote, writer, f"{host}→client"),
        )
        return True

    # ── SNI-rewrite tunnel ────────────────────────────────────────

    async def _do_sni_rewrite_tunnel(self, host: str, port: int, reader, writer,
                                     connect_ip: str | None = None):
        """MITM-decrypt TLS from browser, then re-encrypt toward connect_ip
        using SNI=front_domain (e.g. www.google.com).

        The ISP only ever sees SNI=www.google.com in the outgoing handshake,
        hiding the blocked hostname (e.g. www.youtube.com).
        """
        target_ip = connect_ip or self.fronter.connect_host
        sni_out   = self.fronter.sni_host  # e.g. "www.google.com"

        # Step 1: MITM — accept TLS from the browser
        ssl_ctx_server = self.mitm.get_server_context(host)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol  = transport.get_protocol()
        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx_server, server_side=True,
            )
        except Exception as e:
            log.debug("SNI-rewrite TLS accept failed (%s): %s", host, e)
            return
        writer._transport = new_transport

        # Step 2: open outgoing TLS to target IP with the safe SNI
        ssl_ctx_client = ssl.create_default_context()
        if certifi is not None:
            try:
                ssl_ctx_client.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        if not self.fronter.verify_ssl:
            ssl_ctx_client.check_hostname = False
            ssl_ctx_client.verify_mode = ssl.CERT_NONE
        try:
            r_out, w_out = await asyncio.wait_for(
                asyncio.open_connection(
                    target_ip, port,
                    ssl=ssl_ctx_client,
                    server_hostname=sni_out,
                ),
                timeout=self._tcp_connect_timeout,
            )
        except Exception as e:
            log.error("SNI-rewrite outbound connect failed (%s via %s): %s",
                      host, target_ip, e)
            return

        # Step 3: pipe application-layer bytes between the two TLS sessions
        async def pipe(src, dst, label):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as exc:
                log.debug("Pipe %s ended: %s", label, exc)
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(reader, w_out, f"client→{host}"),
            pipe(r_out,  writer, f"{host}→client"),
        )

    # ── MITM CONNECT (apps_script mode) ───────────────────────────

    async def _do_plain_http_tunnel(self, host: str, port: int, reader, writer):
        """Handle plain HTTP over SOCKS5 in apps_script mode."""
        log.info("Plain HTTP relay → %s:%d", host, port)
        await self._relay_http_stream(host, port, reader, writer)

    async def _do_mitm_connect(self, host: str, port: int, reader, writer):
        """Intercept TLS, decrypt HTTP, and relay through Apps Script."""
        ssl_ctx = self.mitm.get_server_context(host)

        # Upgrade the existing connection to TLS (we are the server)
        loop = asyncio.get_running_loop()
        transport = writer.transport
        protocol = transport.get_protocol()

        try:
            new_transport = await loop.start_tls(
                transport, protocol, ssl_ctx, server_side=True,
            )
        except Exception as e:
            # TLS handshake failed. Common causes:
            #   • Telegram Desktop / MTProto over port 443 sends obfuscated
            #     non-TLS bytes — we literally cannot decrypt these, and
            #     since the target IP is blocked we can't direct-tunnel
            #     either. Telegram will rotate to another DC on its own;
            #     failing fast here lets that happen sooner.
            #   • Client CONNECTs but never speaks TLS (some probes).
            if _is_ip_literal(host) and port == 443:
                log.info(
                    "Non-TLS traffic on %s:%d (likely Telegram MTProto / "
                    "obfuscated protocol). This DC appears blocked; the "
                    "client should rotate to another endpoint shortly.",
                    host, port,
                )
            elif port != 443:
                log.debug(
                    "TLS handshake skipped for %s:%d (non-HTTPS): %s",
                    host, port, e,
                )
            else:
                log.debug("TLS handshake failed for %s: %s", host, e)
            # Close the client side so it fails fast and can retry, rather
            # than hanging on a half-open connection.
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass
            return

        # Update writer to use the new TLS transport
        writer._transport = new_transport

        await self._relay_http_stream(host, port, reader, writer)

    async def _relay_http_stream(self, host: str, port: int, reader, writer):
        """Read decrypted/origin-form HTTP requests and relay them."""
        # Read and relay HTTP requests from the browser (now decrypted)
        while True:
            try:
                first_line = await asyncio.wait_for(
                    reader.readline(), timeout=CLIENT_IDLE_TIMEOUT
                )
                if not first_line:
                    break

                header_block = first_line
                oversized_headers = False
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=10)
                    header_block += line
                    if len(header_block) > MAX_HEADER_BYTES:
                        oversized_headers = True
                        break
                    if line in (b"\r\n", b"\n", b""):
                        break

                # Reject truncated / oversized header blocks cleanly rather
                # than forwarding a half-parsed request to the relay — doing
                # so would send malformed JSON payloads to Apps Script and
                # leave the client hanging until its own timeout fires.
                if oversized_headers:
                    log.warning(
                        "MITM header block exceeds %d bytes — closing (%s)",
                        MAX_HEADER_BYTES, host,
                    )
                    try:
                        writer.write(
                            b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                            b"Connection: close\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await writer.drain()
                    except Exception:
                        pass
                    break

                # Read body
                body = b""
                if _has_unsupported_transfer_encoding(header_block):
                    log.warning("Unsupported Transfer-Encoding → %s:%d", host, port)
                    writer.write(
                        b"HTTP/1.1 501 Not Implemented\r\n"
                        b"Connection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                    await writer.drain()
                    break
                length = _parse_content_length(header_block)
                if length > MAX_REQUEST_BODY_BYTES:
                    raise ValueError(f"Request body too large: {length} bytes")
                if length > 0:
                    body = await reader.readexactly(length)

                # Parse the request
                request_line = first_line.decode(errors="replace").strip()
                parts = request_line.split(" ", 2)
                if len(parts) < 2:
                    break

                method = parts[0]
                path = parts[1]

                # Parse headers
                headers = {}
                for raw_line in header_block.split(b"\r\n")[1:]:
                    if b":" in raw_line:
                        k, v = raw_line.decode(errors="replace").split(":", 1)
                        headers[k.strip()] = v.strip()

                # Shortening the length of X API URLs to prevent relay errors.
                if (host == "x.com" or host == "twitter.com") and  re.match(r"/i/api/graphql/[^/]+/[^?]+\?variables=", path):
                    path = path.split("&")[0]

                # MITM traffic arrives as origin-form paths; SOCKS/plain HTTP can
                # also send absolute-form requests. Normalize both to full URLs.
                if path.startswith("http://") or path.startswith("https://"):
                    url = path
                elif port == 443:
                    url = f"https://{host}{path}"
                elif port == 80:
                    url = f"http://{host}{path}"
                else:
                    url = f"http://{host}:{port}{path}"

                log.info("MITM → %s %s", method, url)

                # ── CORS: extract relevant request headers ─────────────
                origin = self._header_value(headers, "origin")
                acr_method = self._header_value(
                    headers, "access-control-request-method",
                )
                acr_headers = self._header_value(
                    headers, "access-control-request-headers",
                )

                # CORS preflight — respond directly. Apps Script's
                # UrlFetchApp does not support the OPTIONS method, so
                # forwarding preflights would always fail and break every
                # cross-origin fetch/XHR the browser runs through us.
                if method.upper() == "OPTIONS" and acr_method:
                    log.debug(
                        "CORS preflight → %s (responding locally)",
                        url[:60],
                    )
                    writer.write(self._cors_preflight_response(
                        origin, acr_method, acr_headers,
                    ))
                    await writer.drain()
                    continue

                if await self._maybe_stream_download(method, url, headers, body, writer):
                    continue

                # Check local cache first (GET only)
                response = None
                if self._cache_allowed(method, url, headers, body):
                    response = self._cache.get(url)
                    if response:
                        log.debug("Cache HIT: %s", url[:60])

                if response is None:
                    # Relay through Apps Script
                    try:
                        response = await self._relay_smart(method, url, headers, body)
                    except Exception as e:
                        log.error("Relay error (%s): %s", url[:60], e)
                        err_body = f"Relay error: {e}".encode()
                        response = (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: " + str(len(err_body)).encode() + b"\r\n"
                            b"\r\n" + err_body
                        )

                    # Cache successful GET responses
                    if self._cache_allowed(method, url, headers, body) and response:
                        ttl = ResponseCache.parse_ttl(response, url)
                        if ttl > 0:
                            self._cache.put(url, response, ttl)
                            log.debug("Cached (%ds): %s", ttl, url[:60])

                # Inject permissive CORS headers whenever the browser sent
                # an Origin (cross-origin XHR / fetch). Without this, the
                # browser blocks the response even though the relay fetched
                # it successfully.
                if origin and response:
                    response = self._inject_cors_headers(response, origin)

                self._log_response_summary(url, response)

                writer.write(response)
                await writer.drain()

            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            except ConnectionError:
                break
            except Exception as e:
                log.error("MITM handler error (%s): %s", host, e)
                break

    # ── CORS helpers ──────────────────────────────────────────────

    @staticmethod
    def _cors_preflight_response(origin: str, acr_method: str,
                                 acr_headers: str) -> bytes:
        """Build a 204 response that satisfies a CORS preflight locally.

        Apps Script's UrlFetchApp does not support OPTIONS, so we have to
        answer preflights here instead of forwarding them.
        """
        allow_origin = origin or "*"
        allow_methods = (
            f"{acr_method}, GET, POST, PUT, DELETE, PATCH, OPTIONS"
            if acr_method else
            "GET, POST, PUT, DELETE, PATCH, OPTIONS"
        )
        allow_headers = acr_headers or "*"
        return (
            "HTTP/1.1 204 No Content\r\n"
            f"Access-Control-Allow-Origin: {allow_origin}\r\n"
            f"Access-Control-Allow-Methods: {allow_methods}\r\n"
            f"Access-Control-Allow-Headers: {allow_headers}\r\n"
            "Access-Control-Allow-Credentials: true\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "Vary: Origin\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).encode()

    @staticmethod
    def _inject_cors_headers(response: bytes, origin: str) -> bytes:
        """Strip existing Access-Control-* headers and add permissive ones.

        Keeps the body untouched; only rewrites the header block. Using
        the exact browser-supplied Origin (rather than "*") is required
        when the request is credentialed (cookies, Authorization).
        """
        sep = b"\r\n\r\n"
        if sep not in response:
            return response
        header_section, body = response.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        lines = [ln for ln in lines
                 if not ln.lower().startswith("access-control-")]
        allow_origin = origin or "*"
        lines += [
            f"Access-Control-Allow-Origin: {allow_origin}",
            "Access-Control-Allow-Credentials: true",
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers: *",
            "Access-Control-Expose-Headers: *",
            "Vary: Origin",
        ]
        return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    async def _relay_smart(self, method, url, headers, body):
        """Choose optimal relay strategy based on request type.

        - GET requests for likely-large downloads use parallel-range.
        - All other requests (API calls, HTML, JSON, XHR) go through the
          single-request relay. This avoids injecting a synthetic Range
          header on normal traffic, which some origins honor by returning
          206 — breaking fetch()/XHR on sites like x.com or Cloudflare
          challenge pages.
        """
        if method == "GET" and not body:
            # Respect client's own Range header verbatim.
            if headers:
                for k in headers:
                    if k.lower() == "range":
                        return await self.fronter.relay(
                            method, url, headers, body
                        )
            # Only probe with Range when the URL looks like a big file.
            if self._is_likely_download(url, headers):
                return await self.fronter.relay_parallel(
                    method,
                    url,
                    headers,
                    body,
                    chunk_size=self._download_chunk_size,
                    max_parallel=self._download_max_parallel,
                    max_chunks=self._download_max_chunks,
                    min_size=self._download_min_size,
                )
        return await self.fronter.relay(method, url, headers, body)

    def _is_likely_download(self, url: str, headers: dict) -> bool:
        """Heuristic: is this URL likely a large file download?"""
        path = url.split("?")[0].lower()
        if self._download_any_extension:
            return True
        for ext in self._download_extensions:
            if path.endswith(ext):
                return True
        accept = self._header_value(headers, "accept").lower()
        if any(marker in accept for marker in self._DOWNLOAD_ACCEPT_MARKERS):
            return True
        return False

    async def _maybe_stream_download(self, method: str, url: str,
                                     headers: dict | None, body: bytes,
                                     writer) -> bool:
        if method.upper() != "GET" or body:
            return False
        if headers:
            for key in headers:
                if key.lower() == "range":
                    return False
        effective_headers = headers or {}
        if not self._is_likely_download(url, effective_headers):
            return False
        if not self.fronter.stream_download_allowed(url):
            return False
        return await self.fronter.stream_parallel_download(
            url,
            effective_headers,
            writer,
            chunk_size=self._download_chunk_size,
            max_parallel=self._download_max_parallel,
            max_chunks=self._download_max_chunks,
            min_size=self._download_min_size,
        )

    # ── Plain HTTP forwarding ─────────────────────────────────────

    async def _do_http(self, header_block: bytes, reader, writer):
        body = b""
        if _has_unsupported_transfer_encoding(header_block):
            log.warning("Unsupported Transfer-Encoding on plain HTTP request")
            writer.write(
                b"HTTP/1.1 501 Not Implemented\r\n"
                b"Connection: close\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
            await writer.drain()
            return
        length = _parse_content_length(header_block)
        if length > MAX_REQUEST_BODY_BYTES:
            writer.write(b"HTTP/1.1 413 Content Too Large\r\n\r\n")
            await writer.drain()
            return
        if length > 0:
            body = await reader.readexactly(length)

        first_line = header_block.split(b"\r\n")[0].decode(errors="replace")
        log.info("HTTP → %s", first_line)

        # Parse request and relay through Apps Script
        parts = first_line.strip().split(" ", 2)
        method = parts[0] if parts else "GET"
        url = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for raw_line in header_block.split(b"\r\n")[1:]:
            if b":" in raw_line:
                k, v = raw_line.decode(errors="replace").split(":", 1)
                headers[k.strip()] = v.strip()

        # ── CORS preflight over plain HTTP ─────────────────────────────
        origin = self._header_value(headers, "origin")
        acr_method = self._header_value(headers, "access-control-request-method")
        acr_headers = self._header_value(headers, "access-control-request-headers")
        if method.upper() == "OPTIONS" and acr_method:
            log.debug("CORS preflight (HTTP) → %s (responding locally)", url[:60])
            writer.write(self._cors_preflight_response(
                origin, acr_method, acr_headers,
            ))
            await writer.drain()
            return

        if await self._maybe_stream_download(method, url, headers, body, writer):
            return

        # Cache check for GET
        response = None
        if self._cache_allowed(method, url, headers, body):
            response = self._cache.get(url)
            if response:
                log.debug("Cache HIT (HTTP): %s", url[:60])

        if response is None:
            response = await self._relay_smart(method, url, headers, body)
            # Cache successful GET
            if self._cache_allowed(method, url, headers, body) and response:
                ttl = ResponseCache.parse_ttl(response, url)
                if ttl > 0:
                    self._cache.put(url, response, ttl)

        if origin and response:
            response = self._inject_cors_headers(response, origin)

        self._log_response_summary(url, response)

        writer.write(response)
        await writer.drain()