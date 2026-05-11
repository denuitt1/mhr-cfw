"""Supervisor — owns ProxyServer/DomainFronter lifecycle and config apply."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile

from logging_utils import configure as configure_logging
from proxy_server import ProxyServer

log = logging.getLogger("Supervisor")


_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}

HARD_KEYS = frozenset({
    "listen_host", "listen_port",
    "socks5_host", "socks5_port", "socks5_enabled",
    "auth_key",
    "script_id", "script_ids",
    "google_ip", "front_domain",
})

DASHBOARD_RESTART_KEYS = frozenset({
    "dashboard_enabled", "dashboard_host", "dashboard_port",
})


class Supervisor:
    def __init__(self, config: dict, config_path: str):
        self._config: dict = dict(config)
        self._config_path: str = config_path
        self.proxy: ProxyServer | None = None
        self._proxy_task: asyncio.Task | None = None
        self._stopping: bool = False

    @property
    def config(self) -> dict:
        return dict(self._config)

    @property
    def fronter(self):
        return self.proxy.fronter if self.proxy else None

    async def start(self) -> None:
        self.proxy = ProxyServer(self._config)
        await self.proxy.bind()
        self._proxy_task = asyncio.create_task(self.proxy.serve())
        self._proxy_task.add_done_callback(self._on_proxy_done)

    @staticmethod
    def _on_proxy_done(task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("Proxy task crashed: %r", exc)

    async def stop(self) -> None:
        self._stopping = True
        await self._stop_proxy()

    async def _stop_proxy(self) -> None:
        if self._proxy_task and not self._proxy_task.done():
            self._proxy_task.cancel()
            try:
                await self._proxy_task
            except (asyncio.CancelledError, Exception):
                pass
        self._proxy_task = None
        if self.proxy:
            try:
                await self.proxy.stop()
            except Exception as e:
                log.debug("proxy.stop error: %s", e)
            try:
                await self.proxy.fronter.close()
            except Exception as e:
                log.debug("fronter.close error: %s", e)
        self.proxy = None

    async def wait(self) -> None:
        while not self._stopping:
            task = self._proxy_task
            if task is None or task.done():
                await asyncio.sleep(0.1)
                continue
            try:
                await task
            except asyncio.CancelledError:
                pass

    def _validate(self, new_cfg: dict) -> list[str]:
        errors: list[str] = []
        ak = str(new_cfg.get("auth_key", ""))
        if ak in _PLACEHOLDER_AUTH_KEYS:
            errors.append("auth_key is empty or a placeholder")
        sid = new_cfg.get("script_ids") or new_cfg.get("script_id")
        if not sid:
            errors.append("script_id or script_ids must be set")
        elif isinstance(sid, str) and sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID":
            errors.append("script_id is the placeholder value")
        try:
            lp = int(new_cfg.get("listen_port", 8080))
            sp = int(new_cfg.get("socks5_port", 1080))
        except (TypeError, ValueError):
            errors.append("listen_port / socks5_port must be integers")
            return errors
        if not (1 <= lp <= 65535) or not (1 <= sp <= 65535):
            errors.append("ports must be in 1–65535")
        if (
            new_cfg.get("socks5_enabled", True)
            and lp == sp
            and new_cfg.get("listen_host", "127.0.0.1")
            == new_cfg.get("socks5_host", new_cfg.get("listen_host", "127.0.0.1"))
        ):
            errors.append("listen_port and socks5_port must differ on the same host")
        return errors

    async def apply(self, new_cfg: dict) -> dict:
        errors = self._validate(new_cfg)
        if errors:
            return {"ok": False, "errors": errors, "applied": []}

        old = self._config
        applied: list[str] = []
        needs_rebuild = False
        dashboard_changed: list[str] = []

        for k in DASHBOARD_RESTART_KEYS:
            if old.get(k) != new_cfg.get(k):
                dashboard_changed.append(k)

        for k in HARD_KEYS:
            if old.get(k) != new_cfg.get(k):
                needs_rebuild = True
                applied.append(k)

        if new_cfg.get("log_level") != old.get("log_level"):
            try:
                configure_logging(new_cfg.get("log_level", "INFO"))
                applied.append("log_level")
            except Exception as e:
                log.warning("log_level apply failed: %s", e)

        if needs_rebuild:
            log.info("Hard config change — rebuilding proxy server")
            try:
                await self._stop_proxy()
                self.proxy = ProxyServer(new_cfg)
                await self.proxy.bind()
                self._proxy_task = asyncio.create_task(self.proxy.serve())
                self._proxy_task.add_done_callback(self._on_proxy_done)
            except Exception as e:
                log.error("Rebuild failed: %s — rolling back", e)
                try:
                    self.proxy = ProxyServer(old)
                    await self.proxy.bind()
                    self._proxy_task = asyncio.create_task(self.proxy.serve())
                    self._proxy_task.add_done_callback(self._on_proxy_done)
                except Exception as e2:
                    log.error("Rollback also failed: %s", e2)
                return {
                    "ok": False,
                    "errors": [f"rebuild failed: {e}"],
                    "applied": applied,
                }
        else:
            if self.proxy is not None:
                try:
                    proxy_changed = self.proxy.update_config(new_cfg)
                    applied.extend(proxy_changed)
                except Exception as e:
                    log.warning("proxy update_config error: %s", e)
                try:
                    fronter_changed = self.proxy.fronter.update_config(new_cfg)
                    applied.extend(fronter_changed)
                except Exception as e:
                    log.warning("fronter update_config error: %s", e)

        self._config = dict(new_cfg)
        try:
            self._write_config_atomic(self._config)
        except Exception as e:
            log.error("Config write failed: %s", e)
            return {
                "ok": False,
                "errors": [f"config write failed: {e}"],
                "applied": applied,
            }

        return {
            "ok": True,
            "applied": sorted(set(applied)),
            "rebuilt": needs_rebuild,
            "dashboard_restart_required": dashboard_changed,
            "errors": [],
        }

    def _write_config_atomic(self, cfg: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self._config_path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".config.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(cfg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._config_path)
        except Exception:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise
