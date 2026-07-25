"""Scratch demo — enrich N public IPs through the aggregator, twice.

First pass hits the providers (rate-limited, so no 429). Second pass is served
entirely from cache. Not part of the app.

Usage: python scripts/intel_demo.py [count]
"""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

from app.config import get_settings
from app.core.cache import DbBackedCache, InMemoryTTLCache, TieredCache
from app.core.ratelimit import TokenBucket, get_limiter_registry
from app.intel.abuseipdb import AbuseIPDBClient
from app.intel.aggregator import IntelAggregator
from app.intel.virustotal import VirusTotalClient
from app.store.db import dispose_db, init_db

PUBLIC_IPS = [
    "8.8.8.8", "1.1.1.1", "45.13.2.99", "185.220.101.7", "91.219.236.4",
    "193.27.228.7", "208.67.222.222", "9.9.9.9", "80.82.77.139", "104.244.72.115",
]


async def _run(agg: IntelAggregator, ips: list[str], label: str) -> None:
    print(f"\n=== {label} ===")
    results = await agg.lookup_many([(ip, "ip") for ip in ips])
    for ip, v in zip(ips, results, strict=True):
        if v is None:
            print(f"  {ip:16} no data / clean")
        else:
            cached = "CACHED" if v.cached else "live"
            print(
                f"  {ip:16} score={v.score:5.1f} malicious={v.malicious!s:5} "
                f"sources={[e.source.value for e in v.sources]} [{cached}]"
            )


async def main() -> None:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    ips = PUBLIC_IPS[:count]
    await init_db()

    abuse = AbuseIPDBClient(limiter=TokenBucket(60, 60, burst=10, name="abuseipdb-demo"))
    vt = VirusTotalClient(limiter=get_limiter_registry().get("virustotal"))
    cache = TieredCache(InMemoryTTLCache(), DbBackedCache())
    demo_settings = SimpleNamespace(
        intel_cache_ttl_seconds=get_settings().intel_cache_ttl_seconds,
        intel_source_timeout_seconds=120.0,
        intel_concurrency=1,
    )
    agg = IntelAggregator([abuse, vt], cache, demo_settings)

    try:
        await _run(agg, ips, "First pass (live, rate-limited)")
        await _run(agg, ips, "Second pass (from cache)")
        print("\nmetrics:", agg.metrics())
    finally:
        await dispose_db()


if __name__ == "__main__":
    asyncio.run(main())
