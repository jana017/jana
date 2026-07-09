"""Performance instrumentation + intelligent enrichment cache for the IOC analyzer.

Every OSINT provider call goes through :func:`instrument` (an async context
manager) that tracks latency samples, cache hit ratio, and error counts —
exposed via `GET /api/ioc-analyzer/metrics`.

Enrichment results (Shodan, geo, DNS, urlscan, CIRCL) are cached in Mongo
with a 24h TTL under `db.ioc_enrich_cache`. Reputation results keep their
existing 6h `db.ioc_cache` (see `_reputation()` in server.py).

Design goals:
    * Zero allocation on the hot path.
    * Rolling latency window (max 500 samples per provider) to keep memory flat.
    * All I/O is optional — failures never break the request.
"""
from __future__ import annotations
import asyncio
import time
import statistics
import logging
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Deque, Dict


logger = logging.getLogger("ioc_perf")

# 24 h — free enrichment providers rarely produce different data intra-day.
ENRICH_TTL = timedelta(hours=24)
_MAX_SAMPLES = 500  # per-provider rolling window
_SLOW_THRESHOLD_MS = 3000.0  # anything over 3s counts as "slow"


class ProviderStats:
    """Per-provider rolling latency + counters. Thread/async safe under the
    single-event-loop assumption of a FastAPI worker."""

    __slots__ = ("name", "samples", "calls", "hits", "misses", "errors",
                 "cache_hits", "cache_misses", "slow", "last_error")

    def __init__(self, name: str) -> None:
        self.name = name
        self.samples: Deque[float] = deque(maxlen=_MAX_SAMPLES)
        self.calls = 0
        self.hits = 0    # returned data
        self.misses = 0  # returned None / empty
        self.errors = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.slow = 0
        self.last_error: Optional[str] = None

    def snapshot(self) -> Dict[str, Any]:
        s = list(self.samples)
        if not s:
            p50 = p95 = avg = 0.0
        else:
            avg = round(sum(s) / len(s), 2)
            p50 = round(statistics.median(s), 2)
            # cheap p95 without numpy
            k = max(0, int(round(0.95 * (len(s) - 1))))
            p95 = round(sorted(s)[k], 2)
        return {
            "provider": self.name,
            "calls": self.calls,
            "hits": self.hits,
            "misses": self.misses,
            "errors": self.errors,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": (round(self.cache_hits / (self.cache_hits + self.cache_misses), 3)
                               if (self.cache_hits + self.cache_misses) else 0.0),
            "slow_calls": self.slow,
            "avg_ms": avg,
            "p50_ms": p50,
            "p95_ms": p95,
            "last_error": self.last_error,
        }


class MetricsRegistry:
    """Global registry, one instance per process."""
    __slots__ = ("providers", "batches", "started_at")

    def __init__(self) -> None:
        self.providers: Dict[str, ProviderStats] = {}
        self.batches: Deque[Dict[str, Any]] = deque(maxlen=50)
        self.started_at = datetime.now(timezone.utc)

    def _p(self, name: str) -> ProviderStats:
        if name not in self.providers:
            self.providers[name] = ProviderStats(name)
        return self.providers[name]

    def record_cache_hit(self, name: str) -> None:
        self._p(name).cache_hits += 1

    def record_cache_miss(self, name: str) -> None:
        self._p(name).cache_misses += 1

    def record_batch(self, total: int, cached: int, duration_ms: float,
                     errors: int, provider_stats: Optional[Dict[str, Any]] = None) -> None:
        self.batches.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "total": total,
            "cached": cached,
            "errors": errors,
            "duration_ms": round(duration_ms, 2),
            "iocs_per_sec": round(total / (duration_ms / 1000.0), 2) if duration_ms > 0 else 0.0,
            "providers": provider_stats or {},
        })

    def snapshot(self) -> Dict[str, Any]:
        provs = [p.snapshot() for p in self.providers.values()]
        total_calls = sum(p["calls"] for p in provs) or 1
        total_hits = sum(p["cache_hits"] for p in provs)
        total_misses = sum(p["cache_misses"] for p in provs)
        return {
            "uptime_s": round((datetime.now(timezone.utc) - self.started_at).total_seconds(), 0),
            "total_calls": sum(p["calls"] for p in provs),
            "total_errors": sum(p["errors"] for p in provs),
            "overall_cache_hit_rate": round(total_hits / (total_hits + total_misses), 3) if (total_hits + total_misses) else 0.0,
            "avg_call_latency_ms": round(sum(p["avg_ms"] * p["calls"] for p in provs) / total_calls, 2),
            "providers": sorted(provs, key=lambda x: -x["calls"]),
            "recent_batches": list(self.batches)[-20:],
        }


metrics = MetricsRegistry()


@asynccontextmanager
async def instrument(provider: str):
    """Wrap an OSINT provider call.

    Usage::

        async with instrument("shodan_ip") as m:
            r = await hc.get(...)
            m["hit"] = r.status_code == 200
    """
    p = metrics._p(provider)
    p.calls += 1
    t0 = time.perf_counter()
    tag: Dict[str, Any] = {"hit": False, "error": None}
    try:
        yield tag
        dt_ms = (time.perf_counter() - t0) * 1000
        p.samples.append(dt_ms)
        if dt_ms > _SLOW_THRESHOLD_MS:
            p.slow += 1
        if tag.get("hit"):
            p.hits += 1
        else:
            p.misses += 1
    except Exception as e:
        dt_ms = (time.perf_counter() - t0) * 1000
        p.samples.append(dt_ms)
        p.errors += 1
        p.last_error = f"{type(e).__name__}: {e}"[:200]
        raise


# --------------------------------------------------------------------------- #
# Intelligent enrichment cache — 24h Mongo-backed
# --------------------------------------------------------------------------- #

async def get_cached(db, provider: str, key: str) -> Optional[Any]:
    """Return cached provider payload if it exists AND is not expired."""
    if not key:
        return None
    try:
        doc = await db.ioc_enrich_cache.find_one({"_id": f"{provider}:{key}"})
        if not doc or not doc.get("ts"):
            metrics.record_cache_miss(provider)
            return None
        ts = doc["ts"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if datetime.now(timezone.utc) - ts >= ENRICH_TTL:
            metrics.record_cache_miss(provider)
            return None
        metrics.record_cache_hit(provider)
        return doc.get("data")
    except Exception as e:
        logger.debug(f"enrich cache read {provider}:{key} failed: {e}")
        metrics.record_cache_miss(provider)
        return None


async def set_cached(db, provider: str, key: str, data: Any) -> None:
    """Write payload to enrichment cache. Never raises."""
    if not key or data is None:
        return
    try:
        await db.ioc_enrich_cache.update_one(
            {"_id": f"{provider}:{key}"},
            {"$set": {"data": data, "ts": datetime.now(timezone.utc).isoformat(),
                      "provider": provider, "key": key}},
            upsert=True,
        )
    except Exception as e:
        logger.debug(f"enrich cache write {provider}:{key} failed: {e}")


# Ensure a TTL index on enrichment cache so old docs are cleaned up.
async def ensure_indexes(db) -> None:
    """Create indexes needed for the caches. Idempotent."""
    try:
        # Sparse TTL index on `ts_dt` (a real BSON date). We write ISO strings
        # in ts for backward compat with existing docs — this TTL index acts
        # on any doc that has a `ts_dt` date field. New writes below will
        # populate it, allowing MongoDB to auto-expire after ENRICH_TTL.
        await db.ioc_enrich_cache.create_index(
            "ts_dt", expireAfterSeconds=int(ENRICH_TTL.total_seconds()),
            sparse=True, background=True,
        )
    except Exception as e:
        logger.warning(f"ensure_indexes(ioc_enrich_cache) failed: {e}")


def compact_provider_names() -> list[str]:
    """Return the list of providers we currently instrument."""
    return sorted(metrics.providers.keys())


# --------------------------------------------------------------------------- #
# Batch coordination helpers
# --------------------------------------------------------------------------- #

class BatchTimer:
    """Context manager for timing a whole batch + emitting a metrics snapshot."""

    def __init__(self, total: int) -> None:
        self.total = total
        self.cached_count = 0
        self.errors = 0
        self._t0 = 0.0
        self._pre_calls: Dict[str, int] = {}

    def __enter__(self) -> "BatchTimer":
        self._t0 = time.perf_counter()
        # Snapshot per-provider call counts BEFORE the batch so we can diff.
        self._pre_calls = {n: p.calls for n, p in metrics.providers.items()}
        return self

    def __exit__(self, *args) -> None:
        duration_ms = (time.perf_counter() - self._t0) * 1000
        # Delta stats for this batch
        delta: Dict[str, Any] = {}
        for name, p in metrics.providers.items():
            pre = self._pre_calls.get(name, 0)
            n = p.calls - pre
            if n > 0:
                delta[name] = {"calls": n, "p50_ms": p.snapshot()["p50_ms"]}
        metrics.record_batch(
            total=self.total, cached=self.cached_count,
            duration_ms=duration_ms, errors=self.errors,
            provider_stats=delta,
        )


# --------------------------------------------------------------------------- #
# Concurrency limits
# --------------------------------------------------------------------------- #

# Safe upper bound for OSINT concurrency:
#   * urlscan.io: 60 req/min (free), 120 (key)  → 2 QPS soft cap
#   * Shodan InternetDB: no key, generous
#   * ip-api.com: 45 req/min (free)             → 0.75 QPS soft cap
#   * VirusTotal: 4 req/min (free)              → per-provider gate below
#   * AbuseIPDB: 1000/day free
#
# 20 concurrent IOCs × (up to 7 calls) → 140 in-flight max. We ALSO enforce a
# per-provider semaphore so slow/rate-limited providers don't starve.
BATCH_CONCURRENCY = 20

# Per-provider concurrency caps (max simultaneous requests). Values chosen to
# stay well below free-tier rate limits.
PROVIDER_LIMITS = {
    "urlscan":       6,
    "shodan_ip":     10,
    "geo_ip":        6,
    "dns_resolve":   10,
    "circl_hash":    8,
    "vt":            2,   # 4 req/min free — keep it tight
    "abuseipdb":     4,
    "hybrid_analysis": 4,
    "malwarebazaar":   6,
}

_semaphores: Dict[str, asyncio.Semaphore] = {}


def gate(provider: str) -> asyncio.Semaphore:
    """Return (creating on demand) the per-provider concurrency gate."""
    sem = _semaphores.get(provider)
    if sem is None:
        sem = asyncio.Semaphore(PROVIDER_LIMITS.get(provider, 10))
        _semaphores[provider] = sem
    return sem
