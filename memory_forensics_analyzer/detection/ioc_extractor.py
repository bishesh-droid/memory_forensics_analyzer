import re
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IOC:
    type: str
    value: str
    context: str
    source_plugin: str
    confidence: float
    tags: list = field(default_factory=list)


@dataclass
class IOCReport:
    ip_addresses: list
    domains: list
    urls: list
    file_hashes: list
    mutex_names: list
    registry_keys: list
    email_addresses: list
    file_paths: list
    total_count: int


IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|ws|ga|ml|cf|gq|onion)\b'
)
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]]{4,256}'
)
EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
REGISTRY_PATTERN = re.compile(
    r'(?:HKLM|HKCU|HKU|HKCR|HKCC)\\[^\s"]{5,256}'
)
MUTEX_PATTERN = re.compile(
    r'(?:Global\\|Local\\|Session\\)[^\s"]{3,128}'
)

PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),
    (0xAC100000, 0xAC1FFFFF),
    (0xC0A80000, 0xC0A8FFFF),
    (0x7F000000, 0x7FFFFFFF),
]


class IOCExtractor:

    def __init__(self):
        self._seen = set()

    def extract_from_results(self, analysis_results: dict) -> IOCReport:
        logger.info("Extracting IOCs from %d plugin results", len(analysis_results))
        all_text = self._results_to_text(analysis_results)
        return self.extract_from_text(all_text)

    def extract_from_text(self, text: str) -> IOCReport:
        self._seen.clear()

        ips = self._extract_ips(text)
        domains = self._extract_domains(text)
        urls = self._extract_urls(text)
        hashes = self._extract_hashes(text)
        mutexes = self._extract_mutexes(text)
        reg_keys = self._extract_registry_keys(text)
        emails = self._extract_emails(text)
        paths = self._extract_suspicious_paths(text)

        total = sum(len(x) for x in [ips, domains, urls, hashes, mutexes, reg_keys, emails, paths])
        logger.info("Extracted %d IOCs", total)

        return IOCReport(
            ip_addresses=ips, domains=domains, urls=urls,
            file_hashes=hashes, mutex_names=mutexes,
            registry_keys=reg_keys, email_addresses=emails,
            file_paths=paths, total_count=total,
        )

    def _extract_ips(self, text: str) -> list:
        iocs = []
        for match in IP_PATTERN.finditer(text):
            ip = match.group()
            if ip in self._seen or self._is_private_ip(ip):
                continue
            self._seen.add(ip)
            iocs.append(IOC(
                type="ipv4", value=ip,
                context=text[max(0, match.start() - 50):match.end() + 50],
                source_plugin="", confidence=0.7, tags=["network"],
            ))
        return iocs

    def _extract_domains(self, text: str) -> list:
        iocs = []
        benign = {"microsoft.com", "windows.com", "windowsupdate.com",
                  "google.com", "googleapis.com", "gstatic.com"}
        for match in DOMAIN_PATTERN.finditer(text):
            domain = match.group().lower()
            if domain in self._seen or domain in benign:
                continue
            self._seen.add(domain)
            confidence = 0.8 if domain.endswith((".tk", ".xyz", ".pw", ".onion")) else 0.5
            iocs.append(IOC(
                type="domain", value=domain,
                context=text[max(0, match.start() - 50):match.end() + 50],
                source_plugin="", confidence=confidence, tags=["network"],
            ))
        return iocs

    def _extract_urls(self, text: str) -> list:
        iocs = []
        for match in URL_PATTERN.finditer(text):
            url = match.group()
            if url in self._seen:
                continue
            self._seen.add(url)
            iocs.append(IOC(
                type="url", value=url,
                context=text[max(0, match.start() - 30):match.end() + 30],
                source_plugin="", confidence=0.6, tags=["network"],
            ))
        return iocs

    def _extract_hashes(self, text: str) -> list:
        iocs = []
        for pattern, hash_type in [
            (SHA256_PATTERN, "sha256"),
            (SHA1_PATTERN, "sha1"),
            (MD5_PATTERN, "md5"),
        ]:
            for match in pattern.finditer(text):
                h = match.group().lower()
                if h in self._seen or self._is_trivial_hash(h):
                    continue
                self._seen.add(h)
                iocs.append(IOC(
                    type=hash_type, value=h,
                    context=text[max(0, match.start() - 30):match.end() + 30],
                    source_plugin="", confidence=0.5, tags=["file"],
                ))
        return iocs

    def _extract_mutexes(self, text: str) -> list:
        iocs = []
        for match in MUTEX_PATTERN.finditer(text):
            mutex = match.group()
            if mutex in self._seen:
                continue
            self._seen.add(mutex)
            iocs.append(IOC(
                type="mutex", value=mutex,
                context=text[max(0, match.start() - 30):match.end() + 30],
                source_plugin="", confidence=0.7, tags=["persistence"],
            ))
        return iocs

    def _extract_registry_keys(self, text: str) -> list:
        iocs = []
        suspicious_keys = [
            "Run", "RunOnce", "Winlogon", "Shell",
            "Image File Execution", "AppInit_DLLs",
            "Services", "Notify", "Explorer\\ShellIconOverlay",
        ]
        for match in REGISTRY_PATTERN.finditer(text):
            key = match.group()
            if key in self._seen:
                continue
            self._seen.add(key)
            is_suspicious = any(s.lower() in key.lower() for s in suspicious_keys)
            iocs.append(IOC(
                type="registry_key", value=key,
                context=text[max(0, match.start() - 30):match.end() + 30],
                source_plugin="", confidence=0.8 if is_suspicious else 0.4,
                tags=["persistence"] if is_suspicious else ["registry"],
            ))
        return iocs

    def _extract_emails(self, text: str) -> list:
        iocs = []
        for match in EMAIL_PATTERN.finditer(text):
            email = match.group().lower()
            if email in self._seen:
                continue
            self._seen.add(email)
            iocs.append(IOC(
                type="email", value=email,
                context=text[max(0, match.start() - 30):match.end() + 30],
                source_plugin="", confidence=0.5, tags=["contact"],
            ))
        return iocs

    def _extract_suspicious_paths(self, text: str) -> list:
        iocs = []
        path_pattern = re.compile(r'[A-Z]:\\(?:[^\s"<>|]{2,}\\)*[^\s"<>|]{2,}\.\w{2,4}')
        suspicious_dirs = ["temp", "tmp", "appdata", "programdata", "public", "recycle"]
        for match in path_pattern.finditer(text):
            path = match.group()
            if path in self._seen:
                continue
            if any(d in path.lower() for d in suspicious_dirs):
                self._seen.add(path)
                iocs.append(IOC(
                    type="file_path", value=path,
                    context=text[max(0, match.start() - 30):match.end() + 30],
                    source_plugin="", confidence=0.6, tags=["file"],
                ))
        return iocs

    def _is_private_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            num = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        except ValueError:
            return True
        if num == 0 or parts[0] == "255":
            return True
        for start, end in PRIVATE_RANGES:
            if start <= num <= end:
                return True
        return False

    def _is_trivial_hash(self, h: str) -> bool:
        return h == "0" * len(h) or h == "f" * len(h)

    def _results_to_text(self, results: dict) -> str:
        parts = []
        for plugin, result in results.items():
            if hasattr(result, "rows"):
                for row in result.rows:
                    parts.append(" ".join(str(v) for v in row.values()))
            elif isinstance(result, dict):
                for row in result.get("rows", []):
                    parts.append(" ".join(str(v) for v in row.values()))
        return "\n".join(parts)

    def export_stix(self, report: IOCReport) -> dict:
        objects = []
        for ioc_list in [report.ip_addresses, report.domains, report.urls,
                         report.file_hashes, report.mutex_names]:
            for ioc in ioc_list:
                stix_type = {
                    "ipv4": "ipv4-addr", "domain": "domain-name",
                    "url": "url", "sha256": "file", "sha1": "file",
                    "md5": "file", "mutex": "mutex",
                }.get(ioc.type, "artifact")
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "pattern_type": "stix",
                    "pattern": f"[{stix_type}:value = '{ioc.value}']",
                    "name": f"{ioc.type}: {ioc.value}",
                    "confidence": int(ioc.confidence * 100),
                })
        return {"type": "bundle", "spec_version": "2.1", "objects": objects}
