"""Local web dashboard — loopback-only config + health UI."""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import json
import logging
import os
import platform
import sys
import time

from constants import FRONT_SNI_POOL_GOOGLE
import cert_installer
from mitm import CA_CERT_FILE
import probes

log = logging.getLogger("Dashboard")

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_static")
_STATUS_CACHE_TTL = 10.0
_REQUEST_LIMIT = 1 * 1024 * 1024  # 1 MB cap on dashboard request bodies


_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js":  "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _content_type(path: str) -> str:
    _, ext = os.path.splitext(path)
    return _MIME.get(ext.lower(), "application/octet-stream")


class _RingHandler(logging.Handler):
    def __init__(self, capacity: int = 300):
        super().__init__()
        self.buf: collections.deque = collections.deque(maxlen=capacity)
        self._formatter = logging.Formatter("%(message)s")

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buf.append({
                "ts": record.created,
                "level": record.levelname,
                "name": record.name,
                "msg": self._formatter.format(record),
            })
        except Exception:
            pass


def _system_info() -> dict:
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "hostname": platform.node(),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }


def _lan_info(config: dict) -> dict:
    try:
        from lan_utils import get_lan_ips
    except Exception:
        get_lan_ips = None
    listen_host = config.get("listen_host", "127.0.0.1")
    enabled = bool(config.get("lan_sharing")) or listen_host in ("0.0.0.0", "::")
    http_port = int(config.get("listen_port", 8085))
    addresses: list[str] = []
    socks_addresses: list[str] = []
    if enabled and get_lan_ips is not None:
        try:
            addresses = list(get_lan_ips(http_port))
            if config.get("socks5_enabled", True):
                socks_addresses = list(get_lan_ips(int(config.get("socks5_port", 1080))))
        except Exception:
            pass
    return {
        "enabled": enabled,
        "listen_host": listen_host,
        "http_port": http_port,
        "http_addresses": addresses,
        "socks_addresses": socks_addresses,
    }


class Dashboard:
    def __init__(self, supervisor, host: str, port: int):
        self.supervisor = supervisor
        self.host = host
        self.port = port
        self._server: asyncio.base_events.Server | None = None
        self._serve_task: asyncio.Task | None = None
        self._status_cache: dict | None = None
        self._status_cache_at: float = 0.0
        self._status_lock = asyncio.Lock()
        self._last_probe: dict | None = None
        self._last_probe_at: float = 0.0
        self._probe_ttl: float = 60.0
        self._log_handler = _RingHandler(capacity=300)
        logging.getLogger().addHandler(self._log_handler)

    async def start(self) -> None:
        if not _is_loopback(self.host):
            log.warning(
                "Dashboard configured to bind non-loopback host %s — refusing for safety. "
                "Set dashboard_host to 127.0.0.1.",
                self.host,
            )
            return
        try:
            self._server = await asyncio.start_server(
                self._handle, self.host, self.port,
            )
        except OSError as e:
            log.error("Dashboard listener failed on %s:%d — %s",
                      self.host, self.port, e)
            return
        self._serve_task = asyncio.create_task(self._server.serve_forever())
        logging.getLogger().addHandler(self._log_handler)
        log.info("Dashboard listening on http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        try:
            logging.getLogger().removeHandler(self._log_handler)
        except Exception:
            pass
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
        if self._serve_task and not self._serve_task.done():
            self._serve_task.cancel()
            try:
                await self._serve_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ()
        peer_host = peer[0] if peer else ""
        if peer_host and not _is_loopback(peer_host):
            log.warning("Refused non-loopback peer %s", peer_host)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                return
            try:
                method, path, _ = request_line.decode("iso-8859-1").rstrip("\r\n").split(" ", 2)
            except ValueError:
                await self._write_response(writer, 400, b"bad request")
                return

            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line or line in (b"\r\n", b"\n"):
                    break
                raw = line.decode("iso-8859-1").rstrip("\r\n")
                if ":" in raw:
                    k, v = raw.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length:
                if length > _REQUEST_LIMIT:
                    await self._write_response(writer, 413, b"payload too large")
                    return
                body = await asyncio.wait_for(reader.readexactly(length), timeout=20)

            status, resp_headers, resp_body = await self._dispatch(method, path, body)
            await self._write_response(writer, status, resp_body, resp_headers)

        except asyncio.TimeoutError:
            try:
                await self._write_response(writer, 408, b"request timeout")
            except Exception:
                pass
        except Exception as e:
            log.debug("dashboard handler error: %s", e)
            try:
                await self._write_response(writer, 500, b"internal error")
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _write_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
        headers: dict[str, str] | None = None,
    ) -> None:
        reason = {200: "OK", 201: "Created", 204: "No Content",
                  400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
                  408: "Request Timeout", 413: "Payload Too Large",
                  500: "Internal Server Error"}.get(status, "OK")
        out = bytearray()
        out += f"HTTP/1.1 {status} {reason}\r\n".encode()
        hdrs = dict(headers or {})
        hdrs.setdefault("Content-Length", str(len(body)))
        hdrs.setdefault("Connection", "close")
        hdrs.setdefault("Cache-Control", "no-store")
        for k, v in hdrs.items():
            out += f"{k}: {v}\r\n".encode()
        out += b"\r\n"
        if body:
            out += body
        writer.write(bytes(out))
        await writer.drain()

    @staticmethod
    def _json(payload, status: int = 200) -> tuple[int, dict, bytes]:
        body = json.dumps(payload).encode("utf-8")
        return status, {"Content-Type": "application/json; charset=utf-8"}, body

    async def _dispatch(
        self, method: str, path: str, body: bytes,
    ) -> tuple[int, dict, bytes]:
        route = path.split("?", 1)[0]

        if method == "GET" and route == "/":
            return self._serve_static("index.html")
        if method == "GET" and route.startswith("/static/"):
            return self._serve_static(route[len("/static/"):])

        if method == "GET" and route == "/api/config":
            return self._json(self.supervisor.config)

        if method == "POST" and route == "/api/config":
            return await self._post_config(body)

        if method == "GET" and route == "/api/status":
            return await self._get_status()

        if method == "POST" and route == "/api/status/refresh":
            fronter = self.supervisor.fronter
            if fronter is not None:
                try:
                    self._last_probe = await probes.probe_relay_chain(fronter)
                except Exception as e:
                    self._last_probe = {"ok": False,
                                        "error": f"{type(e).__name__}: {e}"}
                self._last_probe_at = time.time()
            async with self._status_lock:
                snap = await self._build_status_snapshot()
                self._status_cache = snap
                self._status_cache_at = time.time()
            return self._json(snap)

        if method == "POST" and route.startswith("/api/probe/script/"):
            sid = route[len("/api/probe/script/"):]
            return await self._post_probe_script(sid)

        if method == "POST" and route == "/api/probe/worker":
            return await self._post_probe_worker()

        if method == "POST" and route == "/api/probe/upstream":
            return await self._post_probe_upstream()

        if method == "GET" and route == "/api/logs":
            return self._json({"lines": list(self._log_handler.buf)})

        if method == "POST" and route == "/api/cert/install":
            return await self._post_cert_install()
        if method == "POST" and route == "/api/cert/uninstall":
            return await self._post_cert_uninstall()

        if method not in ("GET", "POST"):
            return 405, {}, b"method not allowed"
        return 404, {}, b"not found"

    def _serve_static(self, name: str) -> tuple[int, dict, bytes]:
        if "/" in name or "\\" in name or name.startswith(".."):
            return 404, {}, b"not found"
        full = os.path.join(_STATIC_DIR, name)
        if not os.path.isfile(full):
            return 404, {}, b"not found"
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            return 500, {}, b"read error"
        return 200, {"Content-Type": _content_type(full)}, data

    async def _post_config(self, body: bytes) -> tuple[int, dict, bytes]:
        try:
            new_cfg = json.loads(body or b"{}")
        except json.JSONDecodeError as e:
            return self._json({"ok": False, "errors": [f"invalid JSON: {e}"]}, 400)
        if not isinstance(new_cfg, dict):
            return self._json({"ok": False, "errors": ["body must be a JSON object"]}, 400)


        result = await self.supervisor.apply(new_cfg)
        self._status_cache = None
        status = 200 if result.get("ok") else 400
        return self._json(result, status)

    async def _get_status(self) -> tuple[int, dict, bytes]:
        async with self._status_lock:
            now = time.time()
            if self._status_cache and (now - self._status_cache_at) < _STATUS_CACHE_TTL:
                return self._json(self._status_cache)
            snap = await self._build_status_snapshot()
            self._status_cache = snap
            self._status_cache_at = now
        return self._json(snap)

    async def _build_status_snapshot(self) -> dict:
        cfg = self.supervisor.config
        google_ip = cfg.get("google_ip", "216.239.38.120")
        front_domain = cfg.get("front_domain", "www.google.com")
        sni_pool = list(cfg.get("front_domains") or FRONT_SNI_POOL_GOOGLE)
        upstream_url = (cfg.get("upstream_forwarder_url") or "").strip()

        sni_tasks = [probes.probe_sni(google_ip, name) for name in sni_pool]
        direct_task = probes.probe_sni(google_ip, front_domain)
        upstream_task = (
            probes.probe_upstream_forwarder(upstream_url) if upstream_url
            else None
        )

        gathered = await asyncio.gather(
            asyncio.gather(*sni_tasks),
            direct_task,
            upstream_task if upstream_task else asyncio.sleep(0, result=None),
            return_exceptions=False,
        )
        sni_results, direct_result, upstream_result = gathered

        if upstream_url:
            upstream = {"configured": True, **upstream_result}
        else:
            upstream = {"configured": False,
                        "reason": "set upstream_forwarder_url to enable"}

        fronter = self.supervisor.fronter
        if fronter is not None:
            scripts = [fronter.passive_script_health(s) for s in fronter.script_ids()]
            worker = fronter.passive_chain_health()
        else:
            scripts = []
            worker = {"state": "amber", "reason": "proxy not running"}

        probe = None
        if (
            self._last_probe is not None
            and (time.time() - self._last_probe_at) < self._probe_ttl
        ):
            probe = self._last_probe
            age = int(time.time() - self._last_probe_at)
            if probe.get("ok"):
                lat = probe.get("latency_ms")
                msg = f"probe ok ({lat} ms, {age}s ago)"
                worker = {"state": "green", "reason": msg, "last_seen_s": age}
                for s in scripts:
                    if s.get("state") != "red":
                        s["state"] = "green"
                        s["reason"] = msg
                        s["last_seen_s"] = age
            else:
                err = probe.get("error") or "fail"
                msg = f"probe failed: {err} ({age}s ago)"
                worker = {"state": "red", "reason": msg}
                for s in scripts:
                    if s.get("state") != "red":
                        s["state"] = "red"
                        s["reason"] = msg

        return {
            "sni": sni_results,
            "direct": direct_result,
            "scripts": scripts,
            "worker": worker,
            "upstream": upstream,
            "cert": probes.cert_status(),
            "system": _system_info(),
            "lan": _lan_info(self.supervisor.config),
            "generated_at": time.time(),
        }

    async def _post_probe_script(self, sid: str) -> tuple[int, dict, bytes]:
        sid = (sid or "").strip()
        if not sid:
            return self._json({"ok": False, "error": "missing script id"}, 400)
        result = await probes.probe_gas_health(sid)
        return self._json(result)

    async def _post_probe_worker(self) -> tuple[int, dict, bytes]:
        fronter = self.supervisor.fronter
        if fronter is None:
            return self._json({"ok": False, "error": "proxy not running"}, 400)
        result = await probes.probe_relay_chain(fronter)
        return self._json(result)

    async def _post_probe_upstream(self) -> tuple[int, dict, bytes]:
        url = (self.supervisor.config.get("upstream_forwarder_url") or "").strip()
        if not url:
            return self._json(
                {"ok": False, "configured": False,
                 "error": "upstream_forwarder_url is not set"}, 400,
            )
        result = await probes.probe_upstream_forwarder(url)
        return self._json({"configured": True, **result})

    async def _post_cert_install(self) -> tuple[int, dict, bytes]:
        loop = asyncio.get_running_loop()
        try:
            ok = await loop.run_in_executor(
                None, cert_installer.install_ca, CA_CERT_FILE,
            )
        except Exception as e:
            return self._json({"ok": False, "error": str(e)}, 500)
        return self._json({"ok": bool(ok)})

    async def _post_cert_uninstall(self) -> tuple[int, dict, bytes]:
        loop = asyncio.get_running_loop()
        try:
            ok = await loop.run_in_executor(
                None, cert_installer.uninstall_ca, CA_CERT_FILE,
            )
        except Exception as e:
            return self._json({"ok": False, "error": str(e)}, 500)
        return self._json({"ok": bool(ok)})
