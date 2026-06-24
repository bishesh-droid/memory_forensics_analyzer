import hashlib
import json
import logging
import time
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


@dataclass
class VTResult:
    resource: str
    resource_type: str
    positives: int
    total: int
    scan_date: str
    permalink: str
    detected_names: list
    tags: list
    cached: bool


class VirusTotalClient:

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, cache_db: str = "", rate_limit: int = 4):
        self._api_key = api_key
        self._rate_limit = rate_limit
        self._last_request = 0.0
        self._lock = threading.Lock()
        self._cache_db = cache_db or str(
            Path.home() / ".mfa" / "vt_cache.db"
        )
        self._init_cache()

    def _init_cache(self):
        Path(self._cache_db).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._cache_db)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                resource TEXT PRIMARY KEY,
                result TEXT,
                timestamp REAL
            )
        """)
        conn.commit()
        conn.close()

    def lookup_hash(self, file_hash: str) -> Optional[VTResult]:
        cached = self._get_cached(file_hash)
        if cached:
            return cached

        if not self._api_key:
            logger.warning("No VirusTotal API key configured")
            return None

        self._rate_limit_wait()
        try:
            url = f"{self.API_BASE}/files/{file_hash}"
            req = Request(url, headers={"x-apikey": self._api_key})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            result = self._parse_file_result(data, file_hash)
            self._cache_result(file_hash, result)
            return result
        except HTTPError as e:
            if e.code == 404:
                return VTResult(
                    resource=file_hash, resource_type="file",
                    positives=0, total=0, scan_date="",
                    permalink="", detected_names=[], tags=["not_found"],
                    cached=False,
                )
            logger.error("VT API error: %s", e)
            return None
        except Exception as e:
            logger.error("VT lookup failed: %s", e)
            return None

    def lookup_ip(self, ip: str) -> Optional[VTResult]:
        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached

        if not self._api_key:
            return None

        self._rate_limit_wait()
        try:
            url = f"{self.API_BASE}/ip_addresses/{ip}"
            req = Request(url, headers={"x-apikey": self._api_key})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            result = VTResult(
                resource=ip, resource_type="ip",
                positives=stats.get("malicious", 0) + stats.get("suspicious", 0),
                total=sum(stats.values()),
                scan_date="", permalink="",
                detected_names=[], tags=[], cached=False,
            )
            self._cache_result(f"ip:{ip}", result)
            return result
        except Exception as e:
            logger.error("VT IP lookup failed: %s", e)
            return None

    def lookup_domain(self, domain: str) -> Optional[VTResult]:
        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached

        if not self._api_key:
            return None

        self._rate_limit_wait()
        try:
            url = f"{self.API_BASE}/domains/{domain}"
            req = Request(url, headers={"x-apikey": self._api_key})
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            result = VTResult(
                resource=domain, resource_type="domain",
                positives=stats.get("malicious", 0) + stats.get("suspicious", 0),
                total=sum(stats.values()),
                scan_date="", permalink="",
                detected_names=[], tags=[], cached=False,
            )
            self._cache_result(f"domain:{domain}", result)
            return result
        except Exception as e:
            logger.error("VT domain lookup failed: %s", e)
            return None

    def bulk_lookup(self, iocs: list) -> dict:
        results = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            if ioc_type in ("md5", "sha1", "sha256"):
                results[value] = self.lookup_hash(value)
            elif ioc_type == "ipv4":
                results[value] = self.lookup_ip(value)
            elif ioc_type == "domain":
                results[value] = self.lookup_domain(value)
        return results

    def _parse_file_result(self, data: dict, resource: str) -> VTResult:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        detected = []
        for engine, info in results.items():
            if info.get("category") == "malicious":
                detected.append(f"{engine}: {info.get('result', 'malicious')}")

        return VTResult(
            resource=resource, resource_type="file",
            positives=stats.get("malicious", 0) + stats.get("suspicious", 0),
            total=sum(stats.values()),
            scan_date=attrs.get("last_analysis_date", ""),
            permalink=f"https://www.virustotal.com/gui/file/{resource}",
            detected_names=detected[:20],
            tags=attrs.get("tags", []),
            cached=False,
        )

    def _rate_limit_wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            wait = (60.0 / self._rate_limit) - elapsed
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def _get_cached(self, key: str) -> Optional[VTResult]:
        try:
            conn = sqlite3.connect(self._cache_db)
            row = conn.execute(
                "SELECT result, timestamp FROM vt_cache WHERE resource = ?", (key,)
            ).fetchone()
            conn.close()
            if row:
                age = time.time() - row[1]
                if age < 86400:
                    data = json.loads(row[0])
                    data["cached"] = True
                    return VTResult(**data)
        except Exception:
            pass
        return None

    def _cache_result(self, key: str, result: VTResult):
        try:
            conn = sqlite3.connect(self._cache_db)
            data = {
                "resource": result.resource, "resource_type": result.resource_type,
                "positives": result.positives, "total": result.total,
                "scan_date": result.scan_date, "permalink": result.permalink,
                "detected_names": result.detected_names, "tags": result.tags,
                "cached": False,
            }
            conn.execute(
                "INSERT OR REPLACE INTO vt_cache (resource, result, timestamp) VALUES (?, ?, ?)",
                (key, json.dumps(data), time.time()),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Cache write failed: %s", e)
