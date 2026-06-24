import json
import logging
import time
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    value: str
    indicator_type: str
    source: str
    description: str
    severity: str
    first_seen: str
    last_seen: str
    tags: list


class ThreatFeedAggregator:

    def __init__(self, cache_dir: str = "", otx_key: str = "",
                 abuseipdb_key: str = ""):
        self._cache_dir = cache_dir or str(Path.home() / ".mfa" / "threat_cache")
        Path(self._cache_dir).mkdir(parents=True, exist_ok=True)
        self._otx_key = otx_key
        self._abuseipdb_key = abuseipdb_key
        self._db_path = str(Path(self._cache_dir) / "threats.db")
        self._init_db()
        self._lock = threading.Lock()

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                value TEXT PRIMARY KEY,
                type TEXT,
                source TEXT,
                description TEXT,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                tags TEXT,
                cached_at REAL
            )
        """)
        conn.commit()
        conn.close()

    def check_ip(self, ip: str) -> list:
        results = []
        cached = self._get_cached(ip)
        if cached:
            return cached

        if self._abuseipdb_key:
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result:
                results.append(abuse_result)

        if self._otx_key:
            otx_results = self._check_otx_ip(ip)
            results.extend(otx_results)

        for r in results:
            self._cache_indicator(r)
        return results

    def check_domain(self, domain: str) -> list:
        results = []
        cached = self._get_cached(domain)
        if cached:
            return cached

        if self._otx_key:
            otx_results = self._check_otx_domain(domain)
            results.extend(otx_results)

        for r in results:
            self._cache_indicator(r)
        return results

    def check_hash(self, file_hash: str) -> list:
        cached = self._get_cached(file_hash)
        if cached:
            return cached

        results = []
        if self._otx_key:
            otx_results = self._check_otx_hash(file_hash)
            results.extend(otx_results)

        for r in results:
            self._cache_indicator(r)
        return results

    def bulk_check(self, iocs: list) -> dict:
        results = {}
        for ioc in iocs:
            value = ioc.value if hasattr(ioc, "value") else ioc.get("value", "")
            ioc_type = ioc.type if hasattr(ioc, "type") else ioc.get("type", "")
            if ioc_type == "ipv4":
                results[value] = self.check_ip(value)
            elif ioc_type == "domain":
                results[value] = self.check_domain(value)
            elif ioc_type in ("md5", "sha1", "sha256"):
                results[value] = self.check_hash(value)
        return results

    def _check_abuseipdb(self, ip: str) -> Optional[ThreatIndicator]:
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = Request(url, headers={
                "Key": self._abuseipdb_key,
                "Accept": "application/json",
            })
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            report = data.get("data", {})
            score = report.get("abuseConfidenceScore", 0)
            if score > 0:
                severity = "critical" if score > 75 else "high" if score > 50 else "medium"
                return ThreatIndicator(
                    value=ip, indicator_type="ipv4",
                    source="AbuseIPDB",
                    description=f"Abuse score: {score}%, Reports: {report.get('totalReports', 0)}",
                    severity=severity,
                    first_seen="", last_seen=report.get("lastReportedAt", ""),
                    tags=report.get("usageType", "").split(",") if report.get("usageType") else [],
                )
        except Exception as e:
            logger.debug("AbuseIPDB check failed for %s: %s", ip, e)
        return None

    def _check_otx_ip(self, ip: str) -> list:
        results = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            req = Request(url, headers={"X-OTX-API-KEY": self._otx_key})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            pulses = data.get("pulse_info", {}).get("pulses", [])
            if pulses:
                tags = set()
                for pulse in pulses[:5]:
                    tags.update(pulse.get("tags", []))
                results.append(ThreatIndicator(
                    value=ip, indicator_type="ipv4",
                    source="AlienVault OTX",
                    description=f"Found in {len(pulses)} threat pulses",
                    severity="high" if len(pulses) > 3 else "medium",
                    first_seen="", last_seen="",
                    tags=list(tags)[:10],
                ))
        except Exception as e:
            logger.debug("OTX IP check failed for %s: %s", ip, e)
        return results

    def _check_otx_domain(self, domain: str) -> list:
        results = []
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            req = Request(url, headers={"X-OTX-API-KEY": self._otx_key})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            pulses = data.get("pulse_info", {}).get("pulses", [])
            if pulses:
                results.append(ThreatIndicator(
                    value=domain, indicator_type="domain",
                    source="AlienVault OTX",
                    description=f"Found in {len(pulses)} threat pulses",
                    severity="high" if len(pulses) > 3 else "medium",
                    first_seen="", last_seen="",
                    tags=[],
                ))
        except Exception as e:
            logger.debug("OTX domain check failed for %s: %s", domain, e)
        return results

    def _check_otx_hash(self, file_hash: str) -> list:
        results = []
        hash_type = "FileHash-SHA256" if len(file_hash) == 64 else (
            "FileHash-SHA1" if len(file_hash) == 40 else "FileHash-MD5"
        )
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/{hash_type}/{file_hash}/general"
            req = Request(url, headers={"X-OTX-API-KEY": self._otx_key})
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            pulses = data.get("pulse_info", {}).get("pulses", [])
            if pulses:
                results.append(ThreatIndicator(
                    value=file_hash, indicator_type="hash",
                    source="AlienVault OTX",
                    description=f"Found in {len(pulses)} threat pulses",
                    severity="critical" if len(pulses) > 5 else "high",
                    first_seen="", last_seen="",
                    tags=[],
                ))
        except Exception as e:
            logger.debug("OTX hash check failed: %s", e)
        return results

    def _get_cached(self, value: str) -> list:
        try:
            conn = sqlite3.connect(self._db_path)
            rows = conn.execute(
                "SELECT * FROM indicators WHERE value = ? AND cached_at > ?",
                (value, time.time() - 86400),
            ).fetchall()
            conn.close()
            results = []
            for row in rows:
                results.append(ThreatIndicator(
                    value=row[0], indicator_type=row[1], source=row[2],
                    description=row[3], severity=row[4],
                    first_seen=row[5], last_seen=row[6],
                    tags=json.loads(row[7]) if row[7] else [],
                ))
            return results if results else []
        except Exception:
            return []

    def _cache_indicator(self, indicator: ThreatIndicator):
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                """INSERT OR REPLACE INTO indicators
                   (value, type, source, description, severity, first_seen, last_seen, tags, cached_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (indicator.value, indicator.indicator_type, indicator.source,
                 indicator.description, indicator.severity,
                 indicator.first_seen, indicator.last_seen,
                 json.dumps(indicator.tags), time.time()),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Cache write failed: %s", e)
