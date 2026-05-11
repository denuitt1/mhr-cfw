"""
GAS Domain fronting relay engine.

Domain fronting via Google Apps Script: POST JSON to script.google.com
(fronted through www.google.com). Apps Script fetches the target URL and
returns the response.

  relay()   — JSON-based HTTP relay through Apps Script
"""

import asyncio
import base64
import hashlib
import json
import logging
import re
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass
from urllib.parse import urlparse

try:
    import certifi
except Exception:  # optional dependency fallback
    certifi = None

import codec
from constants import (
    BATCH_MAX,
    BATCH_WINDOW_MACRO,
    BATCH_WINDOW_MICRO,
    CONN_TTL,
    FRONT_SNI_POOL_GOOGLE,
    MAX_RESPONSE_BODY_BYTES,
    POOL_MAX,
    POOL_MIN_IDLE,
    RELAY_TIMEOUT,
    SCRIPT_BLACKLIST_TTL,
    SEMAPHORE_MAX,
    STATEFUL_HEADER_NAMES,
    STATIC_EXTS,
    STATS_LOG_INTERVAL,
    STATS_LOG_TOP_N,
    TLS_CONNECT_TIMEOUT,
    WARM_POOL_COUNT,
)

log = logging.getLogger("Fronter")


@dataclass
class HostStat:
    """Per-host traffic accounting — useful for profiling slow / heavy sites."""
    requests: int = 0
    cache_hits: int = 0
    bytes: int = 0
    total_latency_ns: int = 0
    errors: int = 0


def _build_sni_pool(front_domain: str, overrides: list | None) -> list[str]:
    """Build the list of SNIs to rotate through on new outbound TLS handshakes.

    Priority:
      1. Explicit `front_domains` list in config (overrides).
      2. If `front_domain` is a Google property, use FRONT_SNI_POOL_GOOGLE
         (all share the same Google edge IP, so rotation is invisible to
         the relay but breaks DPI's "always www.google.com" heuristic).
      3. Fall back to the single configured `front_domain`.
    """
    if overrides:
        seen: set[str] = set()
        out: list[str] = []
        for item in overrides:
            host = str(item).strip().lower().rstrip(".")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
        if out:
            return out
    fd = (front_domain or "").lower().rstrip(".")
    if fd.endswith(".google.com") or fd == "google.com":
        # Ensure the configured front_domain is first (stable default).
        pool = [fd] + [h for h in FRONT_SNI_POOL_GOOGLE if h != fd]
        return pool
    return [fd] if fd else ["www.google.com"]


class DomainFronter:
    _STATIC_EXTS = STATIC_EXTS
    _H2_FAILURE_COOLDOWN = 60.0
    _H2_FAILURE_THRESHOLD = 3
    _DOWNLOAD_STREAM_COOLDOWN = 300.0
    _COALESCE_VARY_HEADERS = (
        "accept",
        "accept-language",
        "user-agent",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
    )
    _SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}

    def __init__(self, config: dict):
        self.connect_host = config.get("google_ip", "216.239.38.120")
        self.sni_host = config.get("front_domain", "www.google.com")
        # SNI rotation pool — rotated per new outbound TLS connection so
        # DPI systems can't fingerprint traffic as "always one SNI".
        self._sni_hosts = _build_sni_pool(
            self.sni_host, config.get("front_domains"),
        )
        self._sni_idx = 0
        self.http_host = "script.google.com"
        # Multi-script round-robin for higher throughput
        script = config.get("script_ids") or config.get("script_id")
        self._script_ids = script if isinstance(script, list) else [script]
        self._script_idx = 0
        self.script_id = self._script_ids[0]  # backward compat / logging
        self._dev_available = False  # True if /dev endpoint works (no redirect, ~400ms faster)

        # Fan-out parallel relay: fire N Apps Script instances concurrently,
        # keep the first successful response, cancel the rest. Script IDs
        # that fail or time out get blacklisted for SCRIPT_BLACKLIST_TTL so
        # a single slow container stops poisoning tail latency.
        try:
            self._parallel_relay = int(config.get("parallel_relay", 1))
        except (TypeError, ValueError):
            self._parallel_relay = 1
        self._parallel_relay = max(1, min(self._parallel_relay,
                                          len(self._script_ids)))
        self._sid_blacklist: dict[str, float] = {}
        self._blacklist_ttl = SCRIPT_BLACKLIST_TTL

        # Per-host stats (requests, cache hits, bytes, cumulative latency).
        self._per_site: dict[str, HostStat] = {}
        self._stats_task: asyncio.Task | None = None

        self._last_ok_via_gas: float = 0.0
        self._last_ok_via_worker_chain: float = 0.0

        self.auth_key = config.get("auth_key", "")
        self.verify_ssl = config.get("verify_ssl", True)
        self._relay_timeout = self._cfg_float(
            config, "relay_timeout", RELAY_TIMEOUT, minimum=1.0,
        )
        self._tls_connect_timeout = self._cfg_float(
            config, "tls_connect_timeout", TLS_CONNECT_TIMEOUT, minimum=1.0,
        )
        self._max_response_body_bytes = self._cfg_int(
            config, "max_response_body_bytes", MAX_RESPONSE_BODY_BYTES,
            minimum=1024,
        )

        # Connection pool — TTL-based, pre-warmed, with concurrency control
        self._pool: list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]] = []
        self._pool_lock = asyncio.Lock()
        self._pool_max = POOL_MAX
        self._conn_ttl = CONN_TTL
        self._semaphore = asyncio.Semaphore(SEMAPHORE_MAX)
        self._warmed = False
        self._refilling = False
        self._pool_min_idle = POOL_MIN_IDLE
        self._maintenance_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._warm_task: asyncio.Task | None = None
        self._bg_tasks: set[asyncio.Task] = set()

        # Batch collector for grouping concurrent relay() calls
        self._batch_lock = asyncio.Lock()
        self._batch_pending: list[tuple[dict, asyncio.Future]] = []
        self._batch_task: asyncio.Task | None = None
        self._batch_window_micro = BATCH_WINDOW_MICRO
        self._batch_window_macro = BATCH_WINDOW_MACRO
        self._batch_max = BATCH_MAX
        self._batch_enabled = True
        self._batch_disabled_at = 0.0
        self._batch_cooldown = 60

        # Request coalescing — dedup concurrent identical GETs
        self._coalesce: dict[str, list[asyncio.Future]] = {}
        self._h2_failure_streak = 0
        self._h2_disabled_until = 0.0
        self._stream_download_disabled_until: dict[str, float] = {}

        # HTTP/2 multiplexing — one connection handles all requests
        self._h2 = None
        try:
            from h2_transport import H2Transport, H2_AVAILABLE
            if H2_AVAILABLE:
                self._h2 = H2Transport(
                    self.connect_host, self.sni_host, self.verify_ssl,
                    sni_hosts=self._sni_hosts,
                )
                log.info("HTTP/2 multiplexing available — "
                         "all requests will share one connection")
        except ImportError:
            pass

        if len(self._sni_hosts) > 1:
            log.info("SNI rotation pool (%d): %s",
                     len(self._sni_hosts), ", ".join(self._sni_hosts))
        if self._parallel_relay > 1:
            log.info("Fan-out relay: %d parallel Apps Script instances per request",
                     self._parallel_relay)

        # Capability log for content encodings.
        log.info("Response codecs: %s", codec.supported_encodings())

    # ── helpers ───────────────────────────────────────────────────

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

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if certifi is not None:
            try:
                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _h2_available(self) -> bool:
        return (
            self._h2 is not None
            and self._h2.is_connected
            and time.time() >= self._h2_disabled_until
        )

    def _record_h2_success(self) -> None:
        self._h2_failure_streak = 0

    def _record_h2_failure(self, exc: Exception) -> None:
        self._h2_failure_streak += 1
        if self._h2_failure_streak >= self._H2_FAILURE_THRESHOLD:
            self._h2_disabled_until = time.time() + self._H2_FAILURE_COOLDOWN
            log.warning(
                "H2 temporarily disabled for %.0fs after %d consecutive failures (%s)",
                self._H2_FAILURE_COOLDOWN,
                self._h2_failure_streak,
                type(exc).__name__,
            )
            self._h2_failure_streak = 0

    def _stream_download_allowed(self, url: str) -> bool:
        host = self._host_key(url)
        if not host:
            return True
        until = self._stream_download_disabled_until.get(host, 0.0)
        if until > time.time():
            return False
        if until:
            self._stream_download_disabled_until.pop(host, None)
        return True

    def _mark_stream_download_failure(self, url: str, reason: str) -> None:
        host = self._host_key(url)
        if not host:
            return
        self._stream_download_disabled_until[host] = (
            time.time() + self._DOWNLOAD_STREAM_COOLDOWN
        )
        log.warning(
            "Parallel streaming disabled for host %s for %.0fs after failure (%s)",
            host, self._DOWNLOAD_STREAM_COOLDOWN, reason,
        )

    def stream_download_allowed(self, url: str) -> bool:
        return self._stream_download_allowed(url)

    async def _open(self):
        """Open a TLS connection to the CDN.

        - TCP_NODELAY is set on the underlying socket so small H2/H1 writes
          aren't held back by Nagle's algorithm (up to ~40 ms per batch).
        - The *server_hostname* parameter sets the **TLS SNI** extension;
          we rotate across `self._sni_hosts` so DPI can't fingerprint
          "always www.google.com" from the client side.
        """
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (self.connect_host, 443))
            return await asyncio.open_connection(
                sock=sock,
                ssl=self._ssl_ctx(),
                server_hostname=self._next_sni(),
            )
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

    def _next_sni(self) -> str:
        """Round-robin the next SNI from the rotation pool."""
        sni = self._sni_hosts[self._sni_idx % len(self._sni_hosts)]
        self._sni_idx += 1
        return sni

    async def _acquire(self):
        """Get a healthy TLS connection from pool (TTL-checked) or open new."""
        now = asyncio.get_running_loop().time()
        async with self._pool_lock:
            while self._pool:
                reader, writer, created = self._pool.pop()
                if (now - created) < self._conn_ttl and not reader.at_eof():
                    # Eagerly replace the connection we just took
                    asyncio.create_task(self._add_conn_to_pool())
                    return reader, writer, created
                try:
                    writer.close()
                except Exception:
                    pass
        reader, writer = await asyncio.wait_for(
            self._open(), timeout=self._tls_connect_timeout
        )
        # Pool was empty — trigger aggressive background refill
        if not self._refilling:
            self._refilling = True
            self._spawn(self._refill_pool())
        return reader, writer, asyncio.get_running_loop().time()

    async def _release(self, reader, writer, created):
        """Return a connection to the pool if still young and healthy."""
        now = asyncio.get_running_loop().time()
        if (now - created) >= self._conn_ttl or reader.at_eof():
            try:
                writer.close()
            except Exception:
                pass
            return
        async with self._pool_lock:
            if len(self._pool) < self._pool_max:
                self._pool.append((reader, writer, created))
            else:
                try:
                    writer.close()
                except Exception:
                    pass

    def _next_script_id(self) -> str:
        """Round-robin across script IDs for load distribution.

        Skips script IDs currently in the short-term blacklist (failing
        or slow) unless *all* are blacklisted, in which case we fall back
        to plain round-robin so traffic can still flow.
        """
        n = len(self._script_ids)
        for _ in range(n):
            sid = self._script_ids[self._script_idx % n]
            self._script_idx += 1
            if not self._is_sid_blacklisted(sid):
                return sid
        # All blacklisted — clear expired entries and fall back.
        self._prune_blacklist(force=True)
        sid = self._script_ids[self._script_idx % n]
        self._script_idx += 1
        return sid

    def _is_sid_blacklisted(self, sid: str) -> bool:
        until = self._sid_blacklist.get(sid, 0.0)
        if until and until > time.time():
            return True
        if until:
            self._sid_blacklist.pop(sid, None)
        return False

    def _blacklist_sid(self, sid: str, reason: str = "") -> None:
        """Blacklist a script ID for SCRIPT_BLACKLIST_TTL seconds."""
        if len(self._script_ids) <= 1:
            return  # Nothing to fall back to — blacklist would be pointless.
        self._sid_blacklist[sid] = time.time() + self._blacklist_ttl
        log.warning("Blacklisted script %s for %ds%s",
                    sid[-8:] if len(sid) > 8 else sid,
                    int(self._blacklist_ttl),
                    f" ({reason})" if reason else "")

    def _prune_blacklist(self, force: bool = False) -> None:
        now = time.time()
        for sid, until in list(self._sid_blacklist.items()):
            if force or until <= now:
                self._sid_blacklist.pop(sid, None)

    def _pick_fanout_sids(self, key: str | None) -> list[str]:
        """Pick up to `parallel_relay` distinct non-blacklisted script IDs.

        The first ID is the stable per-host choice (same as single-shot
        routing); the rest are filled from the remaining pool. This keeps
        session-sensitive hosts pinned to one script while still racing
        extras for lower tail latency.
        """
        if self._parallel_relay <= 1 or len(self._script_ids) <= 1:
            return [self._script_id_for_key(key)]
        primary = self._script_id_for_key(key)
        picked = [primary]
        others = [s for s in self._script_ids
                  if s != primary and not self._is_sid_blacklisted(s)]
        # Round-robin-ish selection from `others`
        for sid in others:
            if len(picked) >= self._parallel_relay:
                break
            picked.append(sid)
        return picked

    @staticmethod
    def _host_key(url_or_host: str | None) -> str:
        """Return a stable routing key for a URL or host string."""
        if not url_or_host:
            return ""
        parsed = urlparse(url_or_host if "://" in url_or_host else f"https://{url_or_host}")
        host = parsed.hostname or url_or_host
        return host.lower().rstrip(".")

    @classmethod
    def _coalesce_key(cls, url: str, headers: dict | None) -> str:
        key = [url]
        if headers:
            lowered = {str(k).lower(): str(v) for k, v in headers.items()}
            for name in cls._COALESCE_VARY_HEADERS:
                value = lowered.get(name)
                if value:
                    key.append(f"{name}={value}")
        return "\n".join(key)

    @classmethod
    def _retry_attempts_for_payload(cls, payload: dict) -> int:
        method = str(payload.get("m", "GET")).upper()
        return 2 if method in cls._SAFE_RETRY_METHODS else 1

    @staticmethod
    def _render_streaming_headers(resp_headers: dict, total_size: int) -> bytes:
        lines = ["HTTP/1.1 200 OK"]
        skip = {
            "transfer-encoding",
            "connection",
            "keep-alive",
            "content-length",
            "content-range",
        }
        for key, value in resp_headers.items():
            if key.lower() in skip:
                continue
            lines.append(f"{key}: {value}")
        lines.append(f"Content-Length: {total_size}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode()

    @staticmethod
    def _parse_content_range(value: str) -> tuple[int, int, int] | None:
        match = re.match(r"^\s*bytes\s+(\d+)-(\d+)/(\d+)\s*$", value or "")
        if not match:
            return None
        start, end, total = (int(group) for group in match.groups())
        if start < 0 or end < start or total <= end:
            return None
        return start, end, total

    @classmethod
    def _validate_range_response(cls, status: int, resp_headers: dict,
                                 body: bytes, start_off: int,
                                 end_off: int,
                                 total_size: int | None = None) -> str | None:
        if status != 206:
            return f"status {status}"
        parsed = cls._parse_content_range(resp_headers.get("content-range", ""))
        if not parsed:
            return "missing/invalid Content-Range"
        got_start, got_end, got_total = parsed
        if got_start != start_off or got_end != end_off:
            return f"Content-Range mismatch {got_start}-{got_end}"
        if total_size is not None and got_total != total_size:
            return f"Content-Range total mismatch {got_total}/{total_size}"
        expected = end_off - start_off + 1
        if len(body) != expected:
            return f"short chunk {len(body)}/{expected} B"
        return None

    @staticmethod
    def _spool_write(file_obj, offset: int, data: bytes) -> None:
        file_obj.seek(offset)
        file_obj.write(data)
        file_obj.flush()

    @staticmethod
    def _spool_read(file_obj, offset: int, size: int) -> bytes:
        file_obj.seek(offset)
        return file_obj.read(size)

    @staticmethod
    def _format_bytes_human(num_bytes: int) -> str:
        value = float(max(0, num_bytes))
        units = ("B", "KiB", "MiB", "GiB", "TiB")
        unit = units[0]
        for unit in units:
            if value < 1024.0 or unit == units[-1]:
                break
            value /= 1024.0
        if unit == "B":
            return f"{int(value)} {unit}"
        return f"{value:.1f} {unit}"

    @staticmethod
    def _format_elapsed_short(seconds: float) -> str:
        total = max(0, int(seconds))
        minutes, secs = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    @staticmethod
    def _render_progress_bar(done: int, total: int, width: int = 34) -> str:
        if total <= 0:
            return "[" + ("-" * width) + "]"
        ratio = max(0.0, min(1.0, done / total))
        filled = min(width, int(round(ratio * width)))
        return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

    @classmethod
    def _progress_line(cls, *, elapsed: float, done: int, total: int,
                       speed_bytes_per_sec: float) -> str:
        return (
            f"[{cls._format_elapsed_short(elapsed)}] "
            f"{cls._render_progress_bar(done, total)} "
            f"{cls._format_bytes_human(done)} / {cls._format_bytes_human(total)} "
            f"({cls._format_bytes_human(int(speed_bytes_per_sec))}/s)"
        )

    async def _relay_payload_h1(self, payload: dict) -> bytes:
        attempts = self._retry_attempts_for_payload(payload)
        async with self._semaphore:
            for attempt in range(attempts):
                try:
                    return await asyncio.wait_for(
                        self._relay_single(payload), timeout=self._relay_timeout,
                    )
                except Exception as exc:
                    if attempt < attempts - 1:
                        log.debug(
                            "H1 relay attempt %d failed (%s: %s), retrying",
                            attempt + 1, type(exc).__name__, exc,
                        )
                        await self._flush_pool()
                    else:
                        raise

    async def _range_probe(self, url: str, headers: dict, start_off: int,
                           end_off: int, *, max_tries: int = 3) -> bytes:
        probe_headers = dict(headers) if headers else {}
        probe_headers["Range"] = f"bytes={start_off}-{end_off}"
        probe_payload = self._build_payload("GET", url, probe_headers, b"")
        last_raw = b""
        last_status = 0
        for attempt in range(max_tries):
            try:
                last_raw = await self._relay_payload_h1(probe_payload)
            except Exception as exc:
                if attempt == max_tries - 1:
                    raise
                log.warning(
                    "Initial range probe %d-%d retry %d/%d failed: %r",
                    start_off, end_off, attempt + 1, max_tries, exc,
                )
                await asyncio.sleep(0.3 * (attempt + 1))
                continue

            last_status, _, _ = self._split_raw_response(last_raw)
            if last_status == 206 or last_status < 500:
                return last_raw
            if attempt < max_tries - 1:
                log.warning(
                    "Initial range probe %d-%d retry %d/%d: status %d",
                    start_off, end_off, attempt + 1, max_tries, last_status,
                )
                await asyncio.sleep(0.3 * (attempt + 1))
        return last_raw

    # ── Per-host stats ────────────────────────────────────────────

    def _record_site(self, url: str, bytes_: int, latency_ns: int,
                     errored: bool) -> None:
        host = self._host_key(url)
        if not host:
            return
        stat = self._per_site.get(host)
        if stat is None:
            stat = HostStat()
            self._per_site[host] = stat
        stat.requests += 1
        stat.bytes += max(0, int(bytes_))
        stat.total_latency_ns += max(0, int(latency_ns))
        if errored:
            stat.errors += 1

    def stats_snapshot(self) -> dict:
        """Return a point-in-time snapshot of traffic + script health."""
        per_site = []
        for host, s in self._per_site.items():
            avg_ms = (s.total_latency_ns / s.requests / 1e6) if s.requests else 0.0
            per_site.append({
                "host": host,
                "requests": s.requests,
                "errors": s.errors,
                "bytes": s.bytes,
                "avg_ms": round(avg_ms, 1),
            })
        per_site.sort(key=lambda x: x["bytes"], reverse=True)
        now = time.time()
        blacklisted = [
            {"sid": sid[-12:] if len(sid) > 12 else sid,
             "expires_in_s": int(max(0, until - now))}
            for sid, until in self._sid_blacklist.items() if until > now
        ]
        return {
            "per_site": per_site,
            "blacklisted_scripts": blacklisted,
            "sni_rotation": list(self._sni_hosts),
            "parallel_relay": self._parallel_relay,
        }

    def _record_chain_health(self, raw: bytes, errored: bool) -> None:
        if errored or not raw:
            return
        now = time.time()
        self._last_ok_via_gas = now
        status, _, _ = self._split_raw_response(raw)
        if 200 <= status < 400:
            self._last_ok_via_worker_chain = now

    def passive_script_health(self, sid: str) -> dict:
        now = time.time()
        sid_short = sid[-12:] if len(sid) > 12 else sid
        base = {"sid": sid, "sid_short": sid_short}
        until = self._sid_blacklist.get(sid, 0.0)
        if until and until > now:
            return {**base,
                    "state": "red",
                    "reason": "blacklisted",
                    "expires_in_s": int(until - now)}
        if self._last_ok_via_gas and (now - self._last_ok_via_gas) < 60:
            return {**base,
                    "state": "green",
                    "reason": "recent relay traffic",
                    "last_seen_s": int(now - self._last_ok_via_gas)}
        return {**base,
                "state": "amber",
                "reason": "no recent traffic"}

    def passive_chain_health(self) -> dict:
        now = time.time()
        if self._last_ok_via_worker_chain and (now - self._last_ok_via_worker_chain) < 60:
            return {
                "state": "green",
                "last_seen_s": int(now - self._last_ok_via_worker_chain),
            }
        if self._last_ok_via_gas and (now - self._last_ok_via_gas) < 60:
            return {
                "state": "amber",
                "reason": "GAS responding but no 2xx upstream lately",
            }
        return {
            "state": "amber",
            "reason": "no recent traffic",
        }

    def script_ids(self) -> list[str]:
        return list(self._script_ids)

    def update_config(self, new_cfg: dict) -> list[str]:
        changed: list[str] = []

        new_relay = self._cfg_float(
            new_cfg, "relay_timeout", RELAY_TIMEOUT, minimum=1.0,
        )
        if new_relay != self._relay_timeout:
            self._relay_timeout = new_relay
            changed.append("relay_timeout")

        new_tls = self._cfg_float(
            new_cfg, "tls_connect_timeout", TLS_CONNECT_TIMEOUT, minimum=1.0,
        )
        if new_tls != self._tls_connect_timeout:
            self._tls_connect_timeout = new_tls
            changed.append("tls_connect_timeout")

        new_max = self._cfg_int(
            new_cfg, "max_response_body_bytes", MAX_RESPONSE_BODY_BYTES,
            minimum=1024,
        )
        if new_max != self._max_response_body_bytes:
            self._max_response_body_bytes = new_max
            changed.append("max_response_body_bytes")

        new_verify = bool(new_cfg.get("verify_ssl", True))
        if new_verify != self.verify_ssl:
            self.verify_ssl = new_verify
            changed.append("verify_ssl")

        try:
            new_parallel = int(new_cfg.get("parallel_relay", 1))
        except (TypeError, ValueError):
            new_parallel = 1
        new_parallel = max(1, min(new_parallel, len(self._script_ids)))
        if new_parallel != self._parallel_relay:
            self._parallel_relay = new_parallel
            changed.append("parallel_relay")

        new_sni = _build_sni_pool(self.sni_host, new_cfg.get("front_domains"))
        if new_sni != self._sni_hosts:
            self._sni_hosts = new_sni
            self._sni_idx = 0
            changed.append("front_domains")

        return changed

    async def _stats_logger(self):
        """Periodically log top hosts by bytes. DEBUG-level, low overhead."""
        interval = STATS_LOG_INTERVAL
        top_n = STATS_LOG_TOP_N
        while True:
            try:
                await asyncio.sleep(interval)
                if not log.isEnabledFor(logging.DEBUG) or not self._per_site:
                    continue
                snap = self.stats_snapshot()
                top = snap["per_site"][:top_n]
                log.debug("── Per-host stats (top %d by bytes) ──", len(top))
                for row in top:
                    log.debug(
                        "  %-40s %5d req  %2d err  %8d KB  avg %7.1f ms",
                        row["host"][:40], row["requests"], row["errors"],
                        row["bytes"] // 1024, row["avg_ms"],
                    )
                if snap["blacklisted_scripts"]:
                    log.debug("  blacklisted scripts: %s",
                              ", ".join(f"{b['sid']} ({b['expires_in_s']}s)"
                                        for b in snap["blacklisted_scripts"]))
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("Stats logger error: %s", e)

    def _script_id_for_key(self, key: str | None = None) -> str:
        """Pick a stable Apps Script ID for a host or fallback to round-robin.

        When multiple deployments are configured, using a stable mapping per
        host reduces IP/session churn for sites that are sensitive to endpoint
        changes. If no key is available, we keep the older round-robin fallback
        so warmup/keepalive traffic still distributes normally.

        Blacklisted IDs are skipped by probing forward in the list until a
        healthy one is found; if none, the stable pick is returned anyway.
        """
        if len(self._script_ids) == 1:
            return self._script_ids[0]
        if not key:
            return self._next_script_id()
        digest = hashlib.sha1(key.encode("utf-8")).digest()
        base = int.from_bytes(digest[:4], "big") % len(self._script_ids)
        n = len(self._script_ids)
        for offset in range(n):
            sid = self._script_ids[(base + offset) % n]
            if not self._is_sid_blacklisted(sid):
                return sid
        return self._script_ids[base]

    def _exec_path(self, url_or_host: str | None = None) -> str:
        """Get the Apps Script endpoint path (/dev or /exec)."""
        sid = self._script_id_for_key(self._host_key(url_or_host))
        return self._exec_path_for_sid(sid)

    def _exec_path_for_sid(self, sid: str) -> str:
        """Build the /macros/s/<sid>/(dev|exec) path for a specific script ID."""
        return f"/macros/s/{sid}/{'dev' if self._dev_available else 'exec'}"
    async def _flush_pool(self):
        """Close all pooled connections (they may be stale after errors)."""
        async with self._pool_lock:
            for _, writer, _ in self._pool:
                try:
                    writer.close()
                except Exception:
                    pass
            self._pool.clear()

    async def _refill_pool(self):
        """Background: open connections in parallel to refill empty pool."""
        try:
            coros = [self._add_conn_to_pool() for _ in range(8)]
            await asyncio.gather(*coros, return_exceptions=True)
        finally:
            self._refilling = False

    async def _add_conn_to_pool(self):
        """Open one TLS connection and add it to the pool."""
        try:
            r, w = await asyncio.wait_for(self._open(), timeout=5)
            t = asyncio.get_running_loop().time()
            async with self._pool_lock:
                if len(self._pool) < self._pool_max:
                    self._pool.append((r, w, t))
                else:
                    try:
                        w.close()
                    except Exception:
                        pass
        except Exception:
            pass

    async def _pool_maintenance(self):
        """Continuously maintain healthy pool levels in background."""
        while True:
            try:
                await asyncio.sleep(3)
                now = asyncio.get_running_loop().time()

                # Purge expired / dead connections
                async with self._pool_lock:
                    alive = []
                    for r, w, t in self._pool:
                        if (now - t) < self._conn_ttl and not r.at_eof():
                            alive.append((r, w, t))
                        else:
                            try:
                                w.close()
                            except Exception:
                                pass
                    self._pool = alive
                    idle = len(self._pool)

                # Refill if below minimum idle threshold
                needed = max(0, self._pool_min_idle - idle)
                if needed > 0:
                    coros = [self._add_conn_to_pool()
                             for _ in range(min(needed, 5))]
                    await asyncio.gather(*coros, return_exceptions=True)

            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _warm_pool(self):
        """Pre-open TLS connections in the background. Never blocks relay()."""
        if self._warmed:
            return
        self._warmed = True
        self._warm_task = self._spawn(self._do_warm())
        # Start continuous pool maintenance
        if self._maintenance_task is None:
            self._maintenance_task = self._spawn(self._pool_maintenance())
        # Periodic per-host stats logger (opt-in via log level)
        if self._stats_task is None:
            self._stats_task = self._spawn(self._stats_logger())
        # Start H2 connection (runs alongside H1 pool)
        if self._h2:
            self._spawn(self._h2_connect_and_warm())
        # H1 container keepalive — runs unconditionally so the Apps Script
        # container never goes cold even when H2 is unavailable.  When H2 IS
        # active its _keepalive_loop skips the ping; they do not double-fire.
        self._spawn(self._h1_container_keepalive())

    def _spawn(self, coro) -> asyncio.Task:
        """Create a task and keep a strong reference for clean cancellation."""
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    async def close(self):
        """Cancel background tasks and close all pooled / H2 connections."""
        tasks = list(self._bg_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._bg_tasks.clear()

        self._warm_task = None
        self._maintenance_task = None
        self._stats_task = None
        self._keepalive_task = None

        await self._flush_pool()

        if self._h2:
            try:
                await self._h2.close()
            except Exception as exc:
                log.debug("h2 close: %s", exc)

    async def _h2_connect(self):
        """Connect the HTTP/2 transport in background."""
        if self._h2 is None:
            return
        if time.time() < self._h2_disabled_until:
            return
        try:
            await self._h2.ensure_connected()
            self._record_h2_success()
            log.info("H2 multiplexing active — one conn handles all requests")
        except Exception as e:
            self._record_h2_failure(e)
            log.warning("H2 connect failed (%s), using H1 pool fallback", e)

    async def _h2_connect_and_warm(self):
        """Connect H2, pre-warm the Apps Script container, start keepalive."""
        await self._h2_connect()
        if self._h2_available():
            self._spawn(self._prewarm_script())
            if self._keepalive_task is None or self._keepalive_task.done():
                self._keepalive_task = self._spawn(self._keepalive_loop())

    async def _prewarm_script(self):
        """Pre-warm Apps Script and detect /dev fast path (no redirect)."""
        payload = json.dumps(
            {"m": "HEAD", "u": "http://example.com/", "k": self.auth_key}
        ).encode()
        hdrs = {"content-type": "application/json"}
        sid = self._script_ids[0]

        # Test /dev endpoint — returns data inline (no 302 redirect).
        # If it works, saves ~400ms per request by eliminating one round trip.
        try:
            dev_path = f"/macros/s/{sid}/dev"
            t0 = time.perf_counter()
            status, _, body = await asyncio.wait_for(
                self._h2.request(
                    method="POST", path=dev_path, host=self.http_host,
                    headers=hdrs, body=payload,
                ),
                timeout=15,
            )
            dt = (time.perf_counter() - t0) * 1000
            data = json.loads(body.decode(errors="replace"))
            if "s" in data:
                self._dev_available = True
                log.info("/dev fast path active (%.0fms, no redirect)", dt)
                return
        except Exception as e:
            log.debug("/dev test failed: %s", e)

        # Fallback: warm up with /exec
        try:
            exec_path = f"/macros/s/{sid}/exec"
            t0 = time.perf_counter()
            await asyncio.wait_for(
                self._h2.request(
                    method="POST", path=exec_path, host=self.http_host,
                    headers=hdrs, body=payload,
                ),
                timeout=15,
            )
            dt = (time.perf_counter() - t0) * 1000
            log.info("Apps Script pre-warmed in %.0fms", dt)
        except Exception as e:
            log.debug("Pre-warm failed: %s", e)

    async def _keepalive_loop(self):
        """Send periodic pings to keep Apps Script warm + H2 connection alive."""
        while True:
            try:
                await asyncio.sleep(240)  # 4 minutes — saves ~90 quota hits/day vs 180s
                                          # Google's container timeout is ~5 min idle
                if not self._h2_available():
                    try:
                        await self._h2.reconnect()
                        self._record_h2_success()
                    except Exception as exc:
                        self._record_h2_failure(exc)
                        continue

                # H2 PING to keep connection alive
                await self._h2.ping()

                # Apps Script keepalive — warm the container
                payload = {"m": "HEAD", "u": "http://example.com/", "k": self.auth_key}
                path = self._exec_path("example.com")
                t0 = time.perf_counter()
                await asyncio.wait_for(
                    self._h2.request(
                        method="POST", path=path, host=self.http_host,
                        headers={"content-type": "application/json"},
                        body=json.dumps(payload).encode(),
                    ),
                    timeout=20,
                )
                dt = (time.perf_counter() - t0) * 1000
                log.debug("Keepalive ping: %.0fms", dt)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug("Keepalive failed: %s", e)

    async def _h1_container_keepalive(self):
        """Keep the Apps Script container warm via H1 when H2 keepalive is absent.

        H2's _keepalive_loop handles pings when H2 is connected.  When H2 is
        unavailable (library not installed, connection dropped) this coroutine
        takes over so the container never goes cold and causes slow cold-starts
        on the first video / streaming request after an idle period.
        """
        while True:
            try:
                await asyncio.sleep(240)   # same cadence as H2 keepalive
                if self._h2_available():
                    continue  # H2 keepalive is already pinging, skip
                payload = self._build_payload(
                    "HEAD", "http://example.com/", {}, b""
                )
                t0 = time.perf_counter()
                # _relay_payload_h1 has its own per-attempt timeout internally;
                # no outer wait_for needed (and adding one with a shorter
                # timeout would cancel valid in-progress relays early).
                await self._relay_payload_h1(payload)
                dt = (time.perf_counter() - t0) * 1000
                log.debug("H1 container keepalive: %.0fms", dt)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("H1 container keepalive failed: %s", exc)

    async def _do_warm(self):
        """Open WARM_POOL_COUNT connections in parallel — failures are fine."""
        count = WARM_POOL_COUNT
        coros = [self._add_conn_to_pool() for _ in range(count)]
        results = await asyncio.gather(*coros, return_exceptions=True)
        opened = sum(1 for r in results if not isinstance(r, Exception))
        log.info("Pre-warmed %d/%d TLS connections", opened, count)

    def _auth_header(self) -> str:
        return f"X-Auth-Key: {self.auth_key}\r\n" if self.auth_key else ""

    # ── Apps Script relay (apps_script mode) ──────────────────────

    async def relay(self, method: str, url: str,
                    headers: dict, body: bytes = b"") -> bytes:
        """Relay an HTTP request through Apps Script.

        Features:
          - Pre-warms TLS connections on first call
          - Coalesces concurrent identical GET requests
          - Batches concurrent calls via fetchAll() (40ms window)
          - Retries once on connection failure
          - Concurrency-limited via semaphore

        Returns a raw HTTP response (status + headers + body).
        """
        if not self._warmed:
            await self._warm_pool()

        payload = self._build_payload(method, url, headers, body)

        t0 = time.perf_counter()
        errored = False
        result: bytes = b""
        try:
            # Stateful/browser-navigation requests should preserve exact ordering
            # and header context; batching/coalescing is reserved for static fetches.
            if self._is_stateful_request(method, url, headers, body):
                result = await self._relay_with_retry(payload)
                return result

            # Coalesce concurrent GETs for the same URL.
            # CRITICAL: do NOT coalesce when a Range header is present —
            # parallel range downloads MUST each hit the server independently.
            has_range = False
            if headers:
                for k in headers:
                    if k.lower() == "range":
                        has_range = True
                        break
            if method == "GET" and not body and not has_range:
                result = await self._coalesced_submit(
                    self._coalesce_key(url, headers), payload,
                )
                return result

            result = await self._batch_submit(payload)
            return result
        except Exception:
            errored = True
            raise
        finally:
            latency_ns = int((time.perf_counter() - t0) * 1e9)
            self._record_site(url, len(result), latency_ns, errored)
            self._record_chain_health(result, errored)

    async def _coalesced_submit(self, key: str, payload: dict) -> bytes:
        """Dedup concurrent requests for the same URL (no Range header).

        Uses `_batch_lock` to atomically check-and-append, preventing a
        race where the owning task's `finally` pops the entry between
        the check and append by a second task.
        """
        loop = asyncio.get_running_loop()
        async with self._batch_lock:
            waiters = self._coalesce.get(key)
            if waiters is not None:
                future = loop.create_future()
                waiters.append(future)
                log.debug("Coalesced request: %s", key.split("\n", 1)[0][:60])
                waiting = True
            else:
                self._coalesce[key] = []
                waiting = False

        if waiting:
            return await future

        try:
            result = await self._batch_submit(payload)
        except Exception as e:
            async with self._batch_lock:
                waiters = self._coalesce.pop(key, [])
            for f in waiters:
                if not f.done():
                    f.set_exception(e)
            raise

        async with self._batch_lock:
            waiters = self._coalesce.pop(key, [])
        for f in waiters:
            if not f.done():
                f.set_result(result)
        return result

    async def relay_parallel(self, method: str, url: str,
                             headers: dict, body: bytes = b"",
                             chunk_size: int = 512 * 1024,
                             max_parallel: int = 8,
                             max_chunks: int = 256,
                             min_size: int = 0) -> bytes:
        """Relay with parallel range acceleration for large downloads.

        Strategy:
          1. Send initial GET with Range: bytes=0-<chunk_size-1>
          2. If target returns 206 (supports ranges), fetch remaining
             chunks concurrently via HTTP/2 multiplexing.
          3. If target returns 200 (no range support) or small file,
             return the single response.

        Since each Apps Script call takes ~2s regardless of payload size,
        we use:
          - 512 KB chunks (fewer relay calls, lower quota pressure)
          - Up to 8 chunks in flight at once via H2 multiplexing
          - Aggregate throughput of ~2 MB per round-trip (~2-3s)
        """
        if method != "GET" or body:
            return await self.relay(method, url, headers, body)

        # Probe: first chunk with Range header
        first_resp = await self._range_probe(url, headers, 0, chunk_size - 1)

        status, resp_hdrs, resp_body = self._split_raw_response(first_resp)

        # No range support → return the single response as-is (status 200
        # from the origin). The client sent a plain GET, so 200 is what it
        # expects.
        if status != 206:
            return first_resp

        # Parse total size from Content-Range: "bytes 0-262143/1048576"
        parsed_range = self._parse_content_range(resp_hdrs.get("content-range", ""))
        if not parsed_range:
            # Can't parse — downgrade to 200 so the client (which sent a
            # plain GET) doesn't get confused by 206 + Content-Range.
            return self._rewrite_206_to_200(first_resp)
        first_start, first_end, total_size = parsed_range
        first_err = self._validate_range_response(
            status, resp_hdrs, resp_body, first_start, first_end, total_size,
        )
        if first_start != 0 or first_err:
            return self._rewrite_206_to_200(first_resp)
        if total_size > self._max_response_body_bytes:
            return self._error_response(
                502,
                "Relay response exceeds cap "
                f"({self._max_response_body_bytes} bytes). "
                "Increase max_response_body_bytes if your system has enough RAM.",
            )
        if min_size > 0 and total_size < min_size:
            return self._rewrite_206_to_200(first_resp)
        if max_chunks > 0:
            required_chunk_size = max(
                chunk_size,
                (total_size + max_chunks - 1) // max_chunks,
            )
            if required_chunk_size != chunk_size:
                log.info(
                    "Parallel download tuning: chunk size raised from %d KB to %d KB "
                    "to keep request count under %d",
                    chunk_size // 1024,
                    required_chunk_size // 1024,
                    max_chunks,
                )
                chunk_size = required_chunk_size

        # Small file: probe already fetched it all. MUST rewrite to 200
        # because the client never sent a Range header — a stray 206 here
        # breaks fetch()/XHR on sites like x.com and Cloudflare challenges.
        if total_size <= chunk_size or len(resp_body) >= total_size:
            return self._rewrite_206_to_200(first_resp)

        # Calculate remaining ranges
        ranges = []
        start = len(resp_body)
        while start < total_size:
            end = min(start + chunk_size - 1, total_size - 1)
            ranges.append((start, end))
            start = end + 1

        log.info("Parallel download: %d bytes, %d chunks of %d KB",
                 total_size, len(ranges) + 1, chunk_size // 1024)

        # Concurrency-limited parallel fetch
        sem = asyncio.Semaphore(max_parallel)
        progress_lock = asyncio.Lock()
        completed_chunks = 1  # first range probe already succeeded
        completed_bytes = len(resp_body)
        last_progress_log = time.perf_counter()
        total_chunks = len(ranges) + 1
        total_bytes = total_size

        async def fetch_range(s, e, max_tries: int = 3):
            nonlocal completed_chunks, completed_bytes, last_progress_log
            async with sem:
                rh_base = dict(headers) if headers else {}
                rh_base["Range"] = f"bytes={s}-{e}"
                payload = self._build_payload("GET", url, rh_base, b"")
                expected = e - s + 1
                last_err = None
                for attempt in range(max_tries):
                    try:
                        raw = await self._relay_payload_h1(payload)
                        chunk_status, chunk_headers, chunk_body = self._split_raw_response(raw)
                        err = self._validate_range_response(
                            chunk_status, chunk_headers, chunk_body,
                            s, e, total_size,
                        )
                        if err is None:
                            now = time.perf_counter()
                            async with progress_lock:
                                completed_chunks += 1
                                completed_bytes += len(chunk_body)
                                should_log = (
                                    completed_chunks == total_chunks
                                    or (now - last_progress_log) >= 5.0
                                )
                                if should_log:
                                    elapsed = max(0.001, now - t0)
                                    speed_bps = completed_bytes / elapsed
                                    log.info(
                                        "Parallel download progress: %s [%d/%d chunks]",
                                        self._progress_line(
                                            elapsed=elapsed,
                                            done=completed_bytes,
                                            total=total_bytes,
                                            speed_bytes_per_sec=speed_bps,
                                        ),
                                        completed_chunks, total_chunks,
                                    )
                                    last_progress_log = now
                            return chunk_body
                        last_err = err
                    except Exception as e_:
                        last_err = repr(e_)
                    log.warning("Range %d-%d retry %d/%d: %s",
                                s, e, attempt + 1, max_tries, last_err)
                    await asyncio.sleep(0.3 * (attempt + 1))
                raise RuntimeError(
                    f"chunk {s}-{e} failed after {max_tries} tries: {last_err}"
                )

        t0 = asyncio.get_running_loop().time()
        results = await asyncio.gather(
            *[fetch_range(s, e) for s, e in ranges],
            return_exceptions=True,
        )
        elapsed = asyncio.get_running_loop().time() - t0

        # Assemble full body
        parts = [resp_body]
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                log.error("Range chunk %d failed: %s", i, r)
                return self._error_response(502, f"Parallel download failed: {r}")
            parts.append(r)

        full_body = b"".join(parts)
        kbs = (len(full_body) / 1024) / elapsed if elapsed > 0 else 0
        log.info(
            "Parallel download complete: %s",
            self._progress_line(
                elapsed=elapsed,
                done=len(full_body),
                total=len(full_body),
                speed_bytes_per_sec=kbs * 1024,
            ),
        )

        # Return as 200 OK (client sent a normal GET)
        result = f"HTTP/1.1 200 OK\r\n"
        skip = {"transfer-encoding", "connection", "keep-alive",
                "content-length", "content-encoding", "content-range"}
        for k, v in resp_hdrs.items():
            if k.lower() not in skip:
                result += f"{k}: {v}\r\n"
        result += f"Content-Length: {len(full_body)}\r\n"
        result += "\r\n"
        return result.encode() + full_body

    async def stream_parallel_download(self, url: str, headers: dict,
                                       writer,
                                       *,
                                       chunk_size: int = 512 * 1024,
                                       max_parallel: int = 8,
                                       max_chunks: int = 256,
                                       min_size: int = 0) -> bool:
        """Stream a large range-capable download to the client incrementally.

        Returns False when the target should fall back to the normal relay
        path (for example no range support or the file is too small).
        Returns True once this method has taken ownership of the client
        response, even if the stream later aborts.
        """
        first_resp = await self._range_probe(url, headers, 0, chunk_size - 1)

        status, resp_hdrs, resp_body = self._split_raw_response(first_resp)
        if status != 206:
            log.info(
                "Streaming download fallback: initial probe returned %s for %s",
                status, url[:80],
            )
            return False

        parsed_range = self._parse_content_range(resp_hdrs.get("content-range", ""))
        if not parsed_range:
            log.info(
                "Streaming download fallback: missing/invalid Content-Range for %s",
                url[:80],
            )
            return False
        first_start, first_end, total_size = parsed_range
        first_err = self._validate_range_response(
            status, resp_hdrs, resp_body, first_start, first_end, total_size,
        )
        if first_start != 0 or first_err:
            log.info(
                "Streaming download fallback: invalid first range (%s) for %s",
                first_err or f"start={first_start}",
                url[:80],
            )
            return False
        if min_size > 0 and total_size < min_size:
            log.info(
                "Streaming download fallback: file too small (%d < %d) for %s",
                total_size, min_size, url[:80],
            )
            return False
        if max_chunks > 0:
            required_chunk_size = max(
                chunk_size,
                (total_size + max_chunks - 1) // max_chunks,
            )
            if required_chunk_size != chunk_size:
                log.info(
                    "Parallel download tuning: chunk size raised from %d KB to %d KB "
                    "to keep request count under %d",
                    chunk_size // 1024,
                    required_chunk_size // 1024,
                    max_chunks,
                )
                chunk_size = required_chunk_size

        if total_size <= chunk_size or len(resp_body) >= total_size:
            writer.write(self._render_streaming_headers(resp_hdrs, total_size))
            writer.write(resp_body)
            await writer.drain()
            return True

        ranges = []
        start = len(resp_body)
        while start < total_size:
            end = min(start + chunk_size - 1, total_size - 1)
            ranges.append((start, end))
            start = end + 1

        log.info("Parallel streaming download: %d bytes, %d chunks of %d KB",
                 total_size, len(ranges) + 1, chunk_size // 1024)

        temp_file = tempfile.TemporaryFile(prefix="mhrvpn_dl_")
        file_lock = asyncio.Lock()
        sem = asyncio.Semaphore(max_parallel)
        cancel_event = asyncio.Event()
        tasks: list[asyncio.Task] = []
        ready = [asyncio.Event() for _ in ranges]
        errors: list[Exception | None] = [None for _ in ranges]
        delivered_chunks = 1
        delivered_bytes = len(resp_body)
        total_chunks = len(ranges) + 1
        last_progress_log = time.perf_counter()
        t0 = time.perf_counter()

        async def _write_progress(force: bool = False) -> None:
            nonlocal last_progress_log
            now = time.perf_counter()
            if not force and (now - last_progress_log) < 5.0:
                return
            elapsed = max(0.001, now - t0)
            speed_bps = delivered_bytes / elapsed
            log.info(
                "Parallel download progress: %s [%d/%d chunks]",
                self._progress_line(
                    elapsed=elapsed,
                    done=delivered_bytes,
                    total=total_size,
                    speed_bytes_per_sec=speed_bps,
                ),
                delivered_chunks, total_chunks,
            )
            last_progress_log = now

        async def fetch_range(index: int, start_off: int, end_off: int,
                              max_tries: int = 3) -> None:
            async with sem:
                base_headers = dict(headers) if headers else {}
                base_headers["Range"] = f"bytes={start_off}-{end_off}"
                payload = self._build_payload("GET", url, base_headers, b"")
                expected = end_off - start_off + 1
                last_err = "unknown"
                try:
                    for attempt in range(max_tries):
                        if cancel_event.is_set():
                            return
                        try:
                            raw = await self._relay_payload_h1(payload)
                            chunk_status, chunk_headers, chunk_body = self._split_raw_response(raw)
                            err = self._validate_range_response(
                                chunk_status, chunk_headers, chunk_body,
                                start_off, end_off, total_size,
                            )
                            if err is None:
                                async with file_lock:
                                    await asyncio.to_thread(
                                        self._spool_write, temp_file, start_off, chunk_body,
                                    )
                                ready[index].set()
                                return
                            last_err = err
                        except Exception as exc:
                            last_err = repr(exc)
                        if cancel_event.is_set():
                            return
                        log.warning("Range %d-%d retry %d/%d: %s",
                                    start_off, end_off, attempt + 1, max_tries, last_err)
                        await asyncio.sleep(0.3 * (attempt + 1))
                    errors[index] = RuntimeError(
                        f"chunk {start_off}-{end_off} failed after {max_tries} tries: {last_err}"
                    )
                    ready[index].set()
                except asyncio.CancelledError:
                    raise

        try:
            writer.write(self._render_streaming_headers(resp_hdrs, total_size))
            writer.write(resp_body)
            await writer.drain()

            for index, (start_off, end_off) in enumerate(ranges):
                tasks.append(asyncio.create_task(fetch_range(index, start_off, end_off)))

            for index, (start_off, end_off) in enumerate(ranges):
                await ready[index].wait()
                if errors[index] is not None:
                    raise errors[index]
                expected = end_off - start_off + 1
                async with file_lock:
                    chunk = await asyncio.to_thread(
                        self._spool_read, temp_file, start_off, expected,
                    )
                if len(chunk) != expected:
                    raise RuntimeError(
                        f"spooled chunk {start_off}-{end_off} was truncated "
                        f"({len(chunk)}/{expected} B)"
                    )
                writer.write(chunk)
                await writer.drain()
                delivered_chunks += 1
                delivered_bytes += len(chunk)
                await _write_progress(force=(index == len(ranges) - 1))

            elapsed = max(0.001, time.perf_counter() - t0)
            log.info(
                "Parallel streaming download complete: %s",
                self._progress_line(
                    elapsed=elapsed,
                    done=total_size,
                    total=total_size,
                    speed_bytes_per_sec=total_size / elapsed,
                ),
            )
            return True
        except (ConnectionError, BrokenPipeError, TimeoutError) as exc:
            log.info("Parallel download cancelled by client: %s", exc)
            cancel_event.set()
            return True
        except Exception as exc:
            self._mark_stream_download_failure(url, str(exc))
            log.error("Parallel streaming download failed (%s): %s", url[:60], exc)
            cancel_event.set()
            try:
                if not writer.is_closing():
                    writer.close()
            except Exception:
                pass
            return True
        finally:
            cancel_event.set()
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            temp_file.close()

    @staticmethod
    def _rewrite_206_to_200(raw: bytes) -> bytes:
        """Rewrite a 206 Partial Content response to 200 OK.

        Used when we probed with a synthetic Range header but the client
        never asked for one. Handing a 206 back to the browser for a plain
        GET breaks XHR/fetch on sites like x.com and Cloudflare challenges
        (they see it as an aborted/partial response). We drop the
        Content-Range header and set Content-Length to the body size.
        """
        sep = b"\r\n\r\n"
        if sep not in raw:
            return raw
        header_section, body = raw.split(sep, 1)
        lines = header_section.decode(errors="replace").split("\r\n")
        if not lines:
            return raw
        # Replace status line
        first = lines[0]
        if " 206" in first:
            lines[0] = first.replace(" 206 Partial Content", " 200 OK")\
                             .replace(" 206", " 200 OK")
        # Drop Content-Range and recalculate Content-Length
        filtered = [lines[0]]
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith("content-range:"):
                continue
            if low.startswith("content-length:"):
                continue
            filtered.append(ln)
        filtered.append(f"Content-Length: {len(body)}")
        return ("\r\n".join(filtered) + "\r\n\r\n").encode() + body

    # Headers that must never be forwarded to the upstream server because
    # they expose the user's real IP address or internal network topology.
    _STRIP_HEADERS: frozenset = frozenset({
        "accept-encoding",       # Apps Script auto-decompresses gzip only
        "x-forwarded-for",       # would leak the client's real IP
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",             # nginx / CDN header that carries real IP
        "forwarded",             # RFC 7239 — same problem
        "via",                   # reveals intermediate proxy hops
        "proxy-authorization",   # never forward credentials to origin
        "proxy-connection",
    })

    def _build_payload(self, method, url, headers, body):
        """Build the JSON relay payload dict."""
        payload = {
            "m": method,
            "u": url,
            # Let the browser/app see origin redirects and cookies directly.
            "r": False,
        }
        if headers:
            # Strip headers that would leak the user's real IP or expose
            # internal proxy metadata to the upstream destination server.
            filt = {k: v for k, v in headers.items()
                    if k.lower() not in self._STRIP_HEADERS}
            payload["h"] = filt if filt else headers
        if body:
            payload["b"] = base64.b64encode(body).decode()
            ct = headers.get("Content-Type") or headers.get("content-type")
            if ct:
                payload["ct"] = ct
        return payload

    @classmethod
    def _is_static_asset_url(cls, url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in cls._STATIC_EXTS)

    @staticmethod
    def _header_value(headers: dict | None, name: str) -> str:
        if not headers:
            return ""
        for key, value in headers.items():
            if key.lower() == name:
                return str(value)
        return ""

    @classmethod
    def _is_stateful_request(cls, method: str, url: str,
                             headers: dict | None, body: bytes) -> bool:
        method = method.upper()
        if method not in {"GET", "HEAD"} or body:
            return True

        if headers:
            for name in STATEFUL_HEADER_NAMES:
                if cls._header_value(headers, name):
                    return True

            accept = cls._header_value(headers, "accept").lower()
            if "text/html" in accept or "application/json" in accept:
                return True

            fetch_mode = cls._header_value(headers, "sec-fetch-mode").lower()
            if fetch_mode in {"navigate", "cors"}:
                return True

        return not cls._is_static_asset_url(url)

    # ── Batch collector ───────────────────────────────────────────

    async def _batch_submit(self, payload: dict) -> bytes:
        """Submit a request to the batch collector. Returns raw HTTP response."""
        # If batching is disabled, retry enabling it after a cooldown.
        if not self._batch_enabled:
            if (
                self._batch_disabled_at > 0
                and (time.time() - self._batch_disabled_at) >= self._batch_cooldown
            ):
                self._batch_enabled = True
                log.info(
                    "Batch mode re-enabled after %ds cooldown",
                    self._batch_cooldown,
                )
            else:
                return await self._relay_with_retry(payload)

        future = asyncio.get_running_loop().create_future()

        async with self._batch_lock:
            self._batch_pending.append((payload, future))

            if len(self._batch_pending) >= self._batch_max:
                # Batch is full — flush now
                batch = self._batch_pending[:]
                self._batch_pending.clear()
                if self._batch_task and not self._batch_task.done():
                    self._batch_task.cancel()
                self._batch_task = None
                self._spawn(self._batch_send(batch))
            elif self._batch_task is None or self._batch_task.done():
                # First request in a new batch window — start timer
                self._batch_task = self._spawn(self._batch_timer())

        return await future

    async def _batch_timer(self):
        """Two-tier batch window: 5ms micro + 45ms macro.

        Single requests (link clicks) get only 5ms delay.
        Burst traffic (page sub-resources, range chunks) gets a 50ms
        window to accumulate, enabling much larger batches.
        """
        # Tier 1: micro-window — detect if burst or single
        await asyncio.sleep(self._batch_window_micro)
        async with self._batch_lock:
            if len(self._batch_pending) <= 1:
                # Single request — send immediately (only 5ms delay)
                if self._batch_pending:
                    batch = self._batch_pending[:]
                    self._batch_pending.clear()
                    self._batch_task = None
                    self._spawn(self._batch_send(batch))
                return

        # Tier 2: burst detected — wait more to accumulate
        await asyncio.sleep(self._batch_window_macro - self._batch_window_micro)
        async with self._batch_lock:
            if self._batch_pending:
                batch = self._batch_pending[:]
                self._batch_pending.clear()
                self._batch_task = None
                self._spawn(self._batch_send(batch))

    async def _batch_send(self, batch: list):
        """Send a batch of requests. Uses fetchAll for multi, single for one."""
        if len(batch) == 1:
            payload, future = batch[0]
            try:
                result = await self._relay_with_retry(payload)
                if not future.done():
                    future.set_result(result)
            except Exception as e:
                if not future.done():
                    future.set_result(self._error_response(502, str(e)))
        else:
            log.info("Batch relay: %d requests", len(batch))
            try:
                results = await self._relay_batch([p for p, _ in batch])
                for (_, future), result in zip(batch, results):
                    if not future.done():
                        future.set_result(result)
            except Exception as e:
                log.warning(
                    "Batch relay failed, disabling batch mode for %ds cooldown. "
                    "Error: %s",
                    self._batch_cooldown, e,
                )
                self._batch_enabled = False
                self._batch_disabled_at = time.time()
                # Fallback: send individually
                tasks = []
                for payload, future in batch:
                    tasks.append(self._relay_fallback(payload, future))
                await asyncio.gather(*tasks)

    async def _relay_fallback(self, payload, future):
        """Fallback: relay a single request from a failed batch."""
        try:
            result = await self._relay_with_retry(payload)
            if not future.done():
                future.set_result(result)
        except Exception as e:
            if not future.done():
                future.set_result(self._error_response(502, str(e)))

    # ── Core relay with retry ─────────────────────────────────────

    async def _relay_with_retry(self, payload: dict) -> bytes:
        """Single relay with one retry on failure. Uses H2 if available."""
        attempts = self._retry_attempts_for_payload(payload)
        # Fan-out: race N Apps Script instances when enabled and H2 is up.
        # Cuts tail latency when one container is slow/cold. Only kicks in
        # if multiple script IDs are configured and the H2 transport is live.
        if (attempts > 1
                and self._parallel_relay > 1
                and len(self._script_ids) > 1
                and self._h2_available()):
            try:
                result = await asyncio.wait_for(
                    self._relay_fanout(payload), timeout=self._relay_timeout,
                )
                self._record_h2_success()
                return result
            except Exception as e:
                self._record_h2_failure(e)
                log.debug("Fan-out relay failed (%s), falling back", e)
                # fall through to single-path logic below

        # Try HTTP/2 first — much faster (multiplexed, no pool checkout)
        if self._h2_available():
            for attempt in range(attempts):
                try:
                    result = await asyncio.wait_for(
                        self._relay_single_h2(payload), timeout=self._relay_timeout
                    )
                    self._record_h2_success()
                    return result
                except Exception as e:
                    self._record_h2_failure(e)
                    if attempt < attempts - 1:
                        log.debug("H2 relay failed (%s), reconnecting", e)
                        try:
                            await self._h2.reconnect()
                            # Do NOT record success here — only a successful relay
                            # response proves the connection works.  Recording
                            # success after reconnect was resetting the failure
                            # streak and causing an infinite reconnect storm.
                        except Exception as reconnect_exc:
                            self._record_h2_failure(reconnect_exc)
                            log.warning("H2 reconnect failed, falling back to H1")
                            break
                    else:
                        # Last H2 attempt failed — fall through to H1 rather
                        # than raising here, which would bypass H1 entirely.
                        log.debug("H2 relay failed on final attempt (%s), "
                                  "falling back to H1", e)
                        break

        # HTTP/1.1 fallback (pool-based)
        async with self._semaphore:
            for attempt in range(attempts):
                try:
                    return await asyncio.wait_for(
                        self._relay_single(payload), timeout=self._relay_timeout
                    )
                except Exception as e:
                    if attempt < attempts - 1:
                        log.debug("Relay attempt %d failed (%s: %s), retrying",
                                  attempt + 1,
                                  type(e).__name__, e)
                        await self._flush_pool()
                    else:
                        raise

    async def _relay_fanout(self, payload: dict) -> bytes:
        """Fire the same relay against N distinct script IDs in parallel.

        Returns the first successful response; cancels the rest as soon as
        one finishes. Any script that raises or loses the race AND later
        fails individually is blacklisted for SCRIPT_BLACKLIST_TTL.
        """
        host_key = self._host_key(payload.get("u"))
        sids = self._pick_fanout_sids(host_key)
        if len(sids) <= 1:
            # Nothing to race against (e.g. all others blacklisted)
            return await self._relay_single_h2_with_sid(payload, sids[0])

        tasks = {
            asyncio.create_task(
                self._relay_single_h2_with_sid(payload, sid)
            ): sid
            for sid in sids
        }
        winner_result: bytes | None = None
        winner_exc: BaseException | None = None
        pending = set(tasks.keys())
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED,
                )
                for t in done:
                    sid = tasks[t]
                    exc = t.exception()
                    if exc is None:
                        winner_result = t.result()
                        return winner_result
                    # This racer failed — blacklist and keep waiting for others
                    self._blacklist_sid(sid, reason=type(exc).__name__)
                    winner_exc = exc
            # All racers failed
            if winner_exc is not None:
                raise winner_exc
            raise RuntimeError("fan-out relay: all racers failed")
        finally:
            for t in pending:
                t.cancel()
            # Drain cancelled tasks so they don't log warnings
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    async def _relay_single_h2(self, payload: dict) -> bytes:
        """Execute a relay through HTTP/2 multiplexing.

        Uses the shared H2 connection — no pool checkout needed.
        Many concurrent calls all share one TLS connection.
        """
        full_payload = dict(payload)
        full_payload["k"] = self.auth_key
        json_body = json.dumps(full_payload).encode()

        path = self._exec_path(payload.get("u"))

        status, headers, body = await self._h2.request(
            method="POST", path=path, host=self.http_host,
            headers={"content-type": "application/json"},
            body=json_body,
        )

        return self._parse_relay_response(body)

    async def _relay_single_h2_with_sid(self, payload: dict,
                                        sid: str) -> bytes:
        """Execute an H2 relay pinned to a specific Apps Script deployment.

        Used by `_relay_fanout` to race multiple script IDs in parallel.
        Mirrors `_relay_single_h2` but ignores the stable-hash routing.
        """
        full_payload = dict(payload)
        full_payload["k"] = self.auth_key
        json_body = json.dumps(full_payload).encode()

        path = self._exec_path_for_sid(sid)

        status, headers, body = await self._h2.request(
            method="POST", path=path, host=self.http_host,
            headers={"content-type": "application/json"},
            body=json_body,
        )

        return self._parse_relay_response(body)

    async def _relay_single(self, payload: dict) -> bytes:
        """Execute a single relay POST → redirect → parse."""
        # Add auth key
        full_payload = dict(payload)
        full_payload["k"] = self.auth_key
        json_body = json.dumps(full_payload).encode()

        path = self._exec_path(payload.get("u"))
        reader, writer, created = await self._acquire()

        try:
            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {self.http_host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(json_body)}\r\n"
                f"Accept-Encoding: gzip\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            writer.write(request.encode() + json_body)
            await writer.drain()

            status, resp_headers, resp_body = await self._read_http_response(reader)

            # Follow redirect chain on the SAME connection
            for _ in range(5):
                if status not in (301, 302, 303, 307, 308):
                    break
                location = resp_headers.get("location")
                if not location:
                    break

                parsed = urlparse(location)
                rpath = parsed.path + ("?" + parsed.query if parsed.query else "")
                if status in (307, 308):
                    redirect_method = "POST"
                    redirect_body = json_body
                else:
                    redirect_method = "GET"
                    redirect_body = b""
                request_lines = [
                    f"{redirect_method} {rpath} HTTP/1.1",
                    f"Host: {parsed.netloc}",
                    "Accept-Encoding: gzip",
                    "Connection: keep-alive",
                ]
                if redirect_body:
                    request_lines.append(f"Content-Length: {len(redirect_body)}")
                request = "\r\n".join(request_lines) + "\r\n\r\n"
                writer.write(request.encode() + redirect_body)
                await writer.drain()
                status, resp_headers, resp_body = await self._read_http_response(reader)

            await self._release(reader, writer, created)
            return self._parse_relay_response(resp_body)

        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            raise

    async def _relay_batch(self, payloads: list[dict]) -> list[bytes]:
        """Send multiple requests in one POST using Apps Script fetchAll."""
        batch_payload = {
            "k": self.auth_key,
            "q": payloads,
        }
        json_body = json.dumps(batch_payload).encode()
        path = self._exec_path(payloads[0].get("u") if payloads else None)

        # Try HTTP/2 first
        if self._h2_available():
            try:
                status, headers, body = await asyncio.wait_for(
                    self._h2.request(
                        method="POST", path=path, host=self.http_host,
                        headers={"content-type": "application/json"},
                        body=json_body,
                    ),
                    timeout=30,
                )
                self._record_h2_success()
                return self._parse_batch_body(body, payloads)
            except Exception as e:
                self._record_h2_failure(e)
                log.debug("H2 batch failed (%s), falling back to H1", e)

        # HTTP/1.1 fallback
        async with self._semaphore:
            reader, writer, created = await self._acquire()
            try:
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {self.http_host}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(json_body)}\r\n"
                    f"Accept-Encoding: gzip\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                writer.write(request.encode() + json_body)
                await writer.drain()

                status, resp_headers, resp_body = await self._read_http_response(reader)

                # Follow redirects
                for _ in range(5):
                    if status not in (301, 302, 303, 307, 308):
                        break
                    location = resp_headers.get("location")
                    if not location:
                        break
                    parsed = urlparse(location)
                    rpath = parsed.path + ("?" + parsed.query if parsed.query else "")
                    if status in (307, 308):
                        redirect_method = "POST"
                        redirect_body = json_body
                    else:
                        redirect_method = "GET"
                        redirect_body = b""
                    request_lines = [
                        f"{redirect_method} {rpath} HTTP/1.1",
                        f"Host: {parsed.netloc}",
                        "Accept-Encoding: gzip",
                        "Connection: keep-alive",
                    ]
                    if redirect_body:
                        request_lines.append(f"Content-Length: {len(redirect_body)}")
                    request = "\r\n".join(request_lines) + "\r\n\r\n"
                    writer.write(request.encode() + redirect_body)
                    await writer.drain()
                    status, resp_headers, resp_body = await self._read_http_response(reader)

                await self._release(reader, writer, created)

            except Exception:
                try:
                    writer.close()
                except Exception:
                    pass
                raise

        return self._parse_batch_body(resp_body, payloads)

    def _parse_batch_body(self, resp_body: bytes,
                          payloads: list[dict]) -> list[bytes]:
        """Parse a batch response body into individual results."""
        text = resp_body.decode(errors="replace").strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            try:
                data = json.loads(m.group()) if m else None
            except json.JSONDecodeError:
                data = None
        if not data:
            raise RuntimeError(f"Bad batch response: {text[:200]}")

        if "e" in data:
            raise RuntimeError(f"Batch error: {data['e']}")

        items = data.get("q", [])
        if len(items) != len(payloads):
            raise RuntimeError(
                f"Batch size mismatch: {len(items)} vs {len(payloads)}"
            )

        results = []
        for item in items:
            results.append(self._parse_relay_json(item))
        return results

    # ── HTTP response reading (keep-alive safe) ──────────────────

    async def _read_http_response(self, reader: asyncio.StreamReader):
        """Read one HTTP response. Keep-alive safe (no read-until-EOF)."""
        raw = b""
        while b"\r\n\r\n" not in raw:
            if len(raw) > 65536:  # 64 KB header size limit
                return 0, {}, b""
            chunk = await asyncio.wait_for(reader.read(8192), timeout=8)
            if not chunk:
                break
            raw += chunk

        if b"\r\n\r\n" not in raw:
            return 0, {}, b""

        header_section, body = raw.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")

        status_line = lines[0].decode(errors="replace")
        m = re.search(r"\d{3}", status_line)
        status = int(m.group()) if m else 0

        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding", "")

        if "chunked" in transfer_encoding:
            body = await self._read_chunked(reader, body)
        elif content_length:
            total = int(content_length)
            if total > self._max_response_body_bytes:
                raise RuntimeError(
                    "Relay response exceeds configured size cap "
                    f"({total} > {self._max_response_body_bytes} bytes)"
                )
            remaining = total - len(body)
            while remaining > 0:
                chunk = await asyncio.wait_for(
                    reader.read(min(remaining, 65536)), timeout=20
                )
                if not chunk:
                    break
                body += chunk
                if len(body) > self._max_response_body_bytes:
                    raise RuntimeError(
                        "Relay response exceeded configured size cap while reading body"
                    )
                remaining -= len(chunk)
        else:
            # No framing — short timeout read (keep-alive safe)
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=2)
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > self._max_response_body_bytes:
                        raise RuntimeError(
                            "Relay response exceeded configured size cap while streaming"
                        )
                except asyncio.TimeoutError:
                    break

        # Auto-decompress (gzip/deflate/br/zstd) from Google frontend
        enc = headers.get("content-encoding", "")
        if enc:
            body = codec.decode(body, enc)
            if len(body) > self._max_response_body_bytes:
                raise RuntimeError(
                    "Decoded relay response exceeded configured size cap"
                )

        return status, headers, body

    async def _read_chunked(self, reader, buf=b""):
        """Incrementally read chunked transfer-encoding."""
        result = b""
        max_body = self._max_response_body_bytes
        while True:
            while b"\r\n" not in buf:
                data = await asyncio.wait_for(reader.read(8192), timeout=20)
                if not data:
                    return result
                buf += data

            end = buf.find(b"\r\n")
            size_str = buf[:end].decode(errors="replace").strip()
            buf = buf[end + 2:]

            if not size_str:
                continue
            try:
                size = int(size_str, 16)
            except ValueError:
                break
            if size == 0:
                break
            if size > max_body or len(result) + size > max_body:
                raise RuntimeError(
                    "Chunked relay response exceeded configured size cap "
                    f"({max_body} bytes)"
                )

            while len(buf) < size + 2:
                data = await asyncio.wait_for(reader.read(65536), timeout=20)
                if not data:
                    result += buf[:size]
                    return result
                buf += data

            result += buf[:size]
            buf = buf[size + 2:]

        return result

    # ── Response parsing ──────────────────────────────────────────

    def _parse_relay_response(self, body: bytes) -> bytes:
        """Parse JSON from Apps Script and reconstruct an HTTP response."""
        text = body.decode(errors="replace").strip()
        if not text:
            return self._error_response(502, "Empty response from relay")

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                except json.JSONDecodeError:
                    return self._error_response(502, f"Bad JSON: {text[:200]}")
            else:
                return self._error_response(502, f"No JSON: {text[:200]}")

        return self._parse_relay_json(data)

    def _parse_relay_json(self, data: dict) -> bytes:
        """Convert a parsed relay JSON dict to raw HTTP response bytes."""
        if "e" in data:
            return self._error_response(502, f"Relay error: {data['e']}")

        status = data.get("s", 200)
        resp_headers = data.get("h", {})
        resp_body = base64.b64decode(data.get("b", ""))
        if len(resp_body) > self._max_response_body_bytes:
            return self._error_response(
                502,
                "Relay response exceeds cap "
                f"({self._max_response_body_bytes} bytes). "
                "Increase max_response_body_bytes if your system has enough RAM.",
            )

        status_text = {200: "OK", 206: "Partial Content",
                       301: "Moved", 302: "Found", 304: "Not Modified",
                       400: "Bad Request", 403: "Forbidden", 404: "Not Found",
                       500: "Internal Server Error"}.get(status, "OK")
        result = f"HTTP/1.1 {status} {status_text}\r\n"

        skip = {"transfer-encoding", "connection", "keep-alive",
                "content-length", "content-encoding"}
        for k, v in resp_headers.items():
            if k.lower() in skip:
                continue
            # Apps Script returns multi-valued headers (e.g. Set-Cookie) as a
            # JavaScript array. Emit each value as its own header line.
            # A single string that holds multiple Set-Cookie values joined
            # with ", " also needs to be split, otherwise the browser sees
            # one malformed cookie and sites like x.com fail.
            values = v if isinstance(v, list) else [v]
            if k.lower() == "set-cookie":
                expanded = []
                for item in values:
                    expanded.extend(self._split_set_cookie(str(item)))
                values = expanded
            for val in values:
                result += f"{k}: {val}\r\n"
        result += f"Content-Length: {len(resp_body)}\r\n"
        result += "\r\n"
        return result.encode() + resp_body

    @staticmethod
    def _split_set_cookie(blob: str) -> list[str]:
        """Split a Set-Cookie string that may contain multiple cookies.

        Apps Script sometimes joins multiple Set-Cookie values with ", ",
        which collides with the comma that legitimately appears inside the
        `Expires` attribute (e.g. "Expires=Wed, 21 Oct 2026 ..."). We split
        only on commas that are immediately followed by a cookie name=value
        pair (token '=' ...), leaving date commas intact.
        """
        if not blob:
            return []
        # Split on ", " but only when the following text looks like the start
        # of a new cookie (a token followed by '=').
        parts = re.split(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)", blob)
        return [p.strip() for p in parts if p.strip()]

    def _split_raw_response(self, raw: bytes):
        """Split a raw HTTP response into (status, headers_dict, body)."""
        if b"\r\n\r\n" not in raw:
            return 0, {}, raw
        header_section, body = raw.split(b"\r\n\r\n", 1)
        lines = header_section.split(b"\r\n")
        m = re.search(r"\d{3}", lines[0].decode(errors="replace"))
        status = int(m.group()) if m else 0
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode(errors="replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body

    def _error_response(self, status: int, message: str) -> bytes:
        body = f"<html><body><h1>{status}</h1><p>{message}</p></body></html>"
        return (
            f"HTTP/1.1 {status} Error\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        ).encode()