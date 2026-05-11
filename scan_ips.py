#!/usr/bin/env python3
"""
Google IP scanner – fetches live CIDRs, resolves famous domains,
and probes IPs with TLS + HTTP HEAD to find working frontend IPs for SNI rotation.
"""

import asyncio
import ipaddress
import ssl
from typing import List, Dict, Tuple, Set, Optional
import aiohttp
import socket

# Constants
FAMOUS_GOOGLE_DOMAINS = [
    "google.com", "www.google.com", "youtube.com", "gmail.com",
    "drive.google.com", "docs.google.com", "maps.google.com",
    "calendar.google.com", "photos.google.com", "news.google.com",
    "translate.google.com", "accounts.google.com", "myaccount.google.com",
    "cloud.google.com", "firebase.google.com", "android.google.com"
]

CIDR_URL = "https://www.gstatic.com/ipranges/goog.json"
PROBE_TIMEOUT = 4.0   # seconds
CONCURRENCY = 8
DEFAULT_MAX_IPS = 100
DEFAULT_BATCH_SIZE = 20


async def resolve_famous_domains() -> Set[str]:
    """Resolve famous Google domains asynchronously using getaddrinfo."""
    loop = asyncio.get_running_loop()
    ips = set()
    for domain in FAMOUS_GOOGLE_DOMAINS:
        try:
            results = await loop.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
            for res in results:
                ips.add(res[4][0])
        except Exception:
            continue
    return ips


async def fetch_google_cidrs() -> List[str]:
    """Download goog.json and return list of IPv4 CIDRs."""
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get(CIDR_URL, timeout=10) as resp:
            data = await resp.json()
    prefixes = data.get("prefixes", [])
    cidrs = [p["ipv4Prefix"] for p in prefixes if "ipv4Prefix" in p]
    return cidrs


def cidr_to_ips(cidr: str, limit: int = 256) -> List[str]:
    """Expand a CIDR block to a list of IP strings, limited to `limit` addresses."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        ips = [str(ip) for ip in net.hosts()][:limit]
        return ips
    except Exception:
        return []


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.IPv4Network(cidr, strict=False)
    except Exception:
        return False


async def probe_one(ip: str, sni: str, google_ip_validation: bool = True) -> Optional[float]:
    """
    Perform TLS handshake + HTTP HEAD request to the given IP.
    Returns latency in milliseconds if successful and (optionally) Google headers present.
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=sni),
            timeout=PROBE_TIMEOUT
        )
        request = f"HEAD / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(1024), timeout=PROBE_TIMEOUT)
        writer.close()
        await writer.wait_closed()

        resp_str = resp.decode(errors="ignore").lower()
        if not resp_str.startswith("http/"):
            return None

        if google_ip_validation:
            if "server: gws" in resp_str or "x-google-" in resp_str or "alt-svc: h3=" in resp_str:
                return (loop.time() - start) * 1000
            return None
        else:
            return (loop.time() - start) * 1000

    except Exception:
        return None


async def validate_ips(ips: List[str], sni: str, google_ip_validation: bool) -> List[Tuple[str, float]]:
    """Test a list of IPs concurrently, return (ip, latency_ms) for working ones."""
    sem = asyncio.Semaphore(CONCURRENCY)
    async def test_one(ip: str):
        async with sem:
            lat = await probe_one(ip, sni, google_ip_validation)
            if lat is not None:
                return (ip, lat)
        return None

    tasks = [test_one(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def run_scan(config: Dict) -> List[Tuple[str, float]]:
    """
    Main entry point. Returns sorted list of (ip, latency_ms) of working IPs,
    fastest first.
    """
    sni = config.get("front_domain", "www.google.com")
    fetch_from_api = config.get("fetch_ips_from_api", True)
    max_ips = config.get("max_ips_to_scan", DEFAULT_MAX_IPS)
    batch_size = config.get("scan_batch_size", DEFAULT_BATCH_SIZE)
    google_ip_validation = config.get("google_ip_validation", True)

    if not fetch_from_api:
        # Static fallback list (a few known Google frontends)
        static_ips = [
            "216.239.38.120", "216.58.212.142", "142.250.80.142",
            "172.217.1.206", "142.251.32.110", "216.239.32.120"
        ]
        print("[scan] Using static IP list (fetch_ips_from_api disabled)")
        working = await validate_ips(static_ips, sni, google_ip_validation)
        return sorted(working, key=lambda x: x[1])

    # Step 1: Resolve famous domains
    print("[scan] Resolving famous Google domains...")
    famous_ips = await resolve_famous_domains()
    print(f"[scan] Resolved {len(famous_ips)} unique IPs")

    # Step 2: Fetch CIDRs from gstatic
    print("[scan] Fetching Google IP ranges...")
    all_cidrs = await fetch_google_cidrs()
    print(f"[scan] Fetched {len(all_cidrs)} IPv4 CIDRs")

    # Step 3: Find CIDRs that contain at least one famous IP
    priority_cidrs = []
    for cidr in all_cidrs:
        for ip in famous_ips:
            if ip_in_cidr(ip, cidr):
                priority_cidrs.append(cidr)
                break
    print(f"[scan] Found {len(priority_cidrs)} priority CIDRs (containing famous IPs)")

    # Step 4: Expand priority CIDRs then others
    priority_ips = []
    for cidr in priority_cidrs:
        priority_ips.extend(cidr_to_ips(cidr, limit=256))
    other_ips = []
    for cidr in all_cidrs:
        if cidr not in priority_cidrs:
            other_ips.extend(cidr_to_ips(cidr, limit=64))

    # Deduplicate
    priority_ips = list(dict.fromkeys(priority_ips))
    other_ips = list(dict.fromkeys(other_ips))
    print(f"[scan] Priority IPs: {len(priority_ips)} | Other IPs: {len(other_ips)}")

    # shuffle
    import random
    random.shuffle(priority_ips)
    random.shuffle(other_ips)

    # Select up to max_ips, favouring priority ones
    selected = priority_ips[:max_ips]
    if len(selected) < max_ips:
        remaining = max_ips - len(selected)
        selected.extend(other_ips[:remaining])

    print(f"[scan] Selected {len(selected)} IPs to test (max {max_ips})")

    # Step 5: Validate in batches
    working = []
    total = len(selected)
    for i in range(0, total, batch_size):
        batch = selected[i:i+batch_size]
        print(f"[scan] Testing batch {i//batch_size + 1}/{(total + batch_size - 1)//batch_size} ({len(batch)} IPs)...")
        batch_working = await validate_ips(batch, sni, google_ip_validation)
        working.extend(batch_working)
        print(f"[scan] Batch found {len(batch_working)} working IPs (total: {len(working)})")

    working.sort(key=lambda x: x[1])
    return working


def scan_sync(config: Dict) -> List[Tuple[str, float]]:
    """Synchronous wrapper for background threads."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(run_scan(config))
    finally:
        loop.close()


