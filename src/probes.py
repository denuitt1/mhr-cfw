"""Probe primitives for the dashboard health surface."""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import ssl
import time
from typing import Optional

from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
except Exception:
    x509 = None
    hashes = None

import cert_installer
from mitm import CA_CERT_FILE

log = logging.getLogger("Probe")


async def probe_sni(ip: str, sni: str, timeout: float = 4.0) -> dict:
    start = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
            timeout=timeout,
        )
        request = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(256), timeout=timeout)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if not response or not response.startswith(b"HTTP/"):
            return {"name": sni, "ok": False, "error": "invalid response"}

        elapsed_ms = int((time.time() - start) * 1000)
        return {"name": sni, "ok": True, "latency_ms": elapsed_ms}

    except asyncio.TimeoutError:
        return {"name": sni, "ok": False, "error": "timeout"}
    except OSError as e:
        return {"name": sni, "ok": False, "error": e.strerror or str(e)}
    except Exception as e:
        return {"name": sni, "ok": False, "error": f"{type(e).__name__}"}


async def probe_https_get(
    url: str,
    timeout: float = 8.0,
    expect_in_body: Optional[bytes] = None,
) -> dict:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"ok": False, "error": "https URL required"}
    host = parsed.hostname
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    start = time.time()
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: mhr-cfw-dashboard/1\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(32 * 1024), timeout=timeout)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        if not raw or not raw.startswith(b"HTTP/"):
            return {"ok": False, "error": "no HTTP response"}
        first_line = raw.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first_line.split(" ", 2)
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        elapsed_ms = int((time.time() - start) * 1000)
        if status < 200 or status >= 400:
            return {"ok": False, "status": status, "latency_ms": elapsed_ms,
                    "error": f"status {status}"}
        if expect_in_body is not None and expect_in_body not in raw:
            return {"ok": False, "status": status, "latency_ms": elapsed_ms,
                    "error": "body marker missing"}
        return {"ok": True, "status": status, "latency_ms": elapsed_ms}

    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except OSError as e:
        return {"ok": False, "error": e.strerror or str(e)}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}"}


async def probe_upstream_forwarder(url: str, timeout: float = 6.0) -> dict:
    base = (url or "").rstrip("/")
    return await probe_https_get(
        base + "/", timeout=timeout, expect_in_body=b"Forwarder Active",
    )


async def probe_gas_health(script_id: str, timeout: float = 8.0) -> dict:
    url = f"https://script.google.com/macros/s/{script_id}/exec"
    return await probe_https_get(url, timeout=timeout, expect_in_body=b"Relay Active")


async def probe_relay_chain(fronter, target_url: str = "https://www.gstatic.com/generate_204",
                            timeout: float = 12.0) -> dict:
    # Uses _relay_payload_h1 directly to avoid updating the passive timestamps that drive script/worker dots.
    payload = fronter._build_payload("GET", target_url, {}, b"")
    start = time.time()
    try:
        raw = await asyncio.wait_for(
            fronter._relay_payload_h1(payload), timeout=timeout,
        )
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    elapsed_ms = int((time.time() - start) * 1000)
    if not raw:
        return {"ok": False, "error": "empty response", "latency_ms": elapsed_ms}
    status, _, _ = fronter._split_raw_response(raw)
    if 200 <= status < 400:
        return {"ok": True, "status": status, "latency_ms": elapsed_ms}
    return {"ok": False, "status": status, "latency_ms": elapsed_ms,
            "error": f"upstream status {status}"}


def cert_status() -> dict:
    info: dict = {"path": CA_CERT_FILE}
    if not os.path.exists(CA_CERT_FILE):
        info.update({"present": False, "is_trusted": False})
        return info
    info["present"] = True
    if x509 is None:
        info["error"] = "cryptography unavailable"
    else:
        try:
            with open(CA_CERT_FILE, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            info["subject"] = cert.subject.rfc4514_string()
            info["issuer"] = cert.issuer.rfc4514_string()
            try:
                not_after = cert.not_valid_after_utc
            except AttributeError:
                not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            info["not_after"] = not_after.isoformat()
            info["expired"] = not_after < datetime.datetime.now(datetime.timezone.utc)
            fp = cert.fingerprint(hashes.SHA256())
            info["fingerprint_sha256"] = ":".join(f"{b:02X}" for b in fp)
        except Exception as e:
            info["error"] = f"parse failed: {e}"
    try:
        info["is_trusted"] = bool(cert_installer.is_ca_trusted(CA_CERT_FILE))
    except Exception as e:
        info["is_trusted"] = False
        info["trust_check_error"] = str(e)
    return info
