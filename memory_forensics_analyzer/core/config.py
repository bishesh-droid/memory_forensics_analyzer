import os
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class AnalysisProfile:
    os_type: str = "windows"
    os_version: str = ""
    architecture: str = "x64"
    kernel_base: int = 0
    dtb: int = 0
    kdbg: int = 0
    build_number: int = 0


@dataclass
class YaraConfig:
    enabled: bool = True
    rules_dir: str = ""
    timeout: int = 60
    max_strings: int = 10000


@dataclass
class ThreatIntelConfig:
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    mitre_attack_version: str = "14.1"
    cache_ttl: int = 86400


@dataclass
class ReportConfig:
    output_dir: str = "reports"
    format: str = "html"
    include_raw_data: bool = False
    company_name: str = ""
    analyst_name: str = ""
    classification: str = "CONFIDENTIAL"


@dataclass
class APIConfig:
    host: str = "127.0.0.1"
    port: int = 8443
    ssl_certfile: str = ""
    ssl_keyfile: str = ""
    api_key: str = ""
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000"])


@dataclass
class DetectionConfig:
    anomaly_threshold: float = 0.7
    entropy_threshold: float = 7.0
    max_injection_size: int = 1048576
    suspicious_parents: dict = field(default_factory=lambda: {
        "svchost.exe": "services.exe",
        "smss.exe": "System",
        "csrss.exe": "smss.exe",
        "wininit.exe": "smss.exe",
        "winlogon.exe": "smss.exe",
        "lsass.exe": "wininit.exe",
        "services.exe": "wininit.exe",
        "taskhost.exe": "services.exe",
        "taskhostw.exe": "svchost.exe",
    })


@dataclass
class CaseConfig:
    case_dir: str = "cases"
    auto_hash: bool = True
    chain_of_custody: bool = True


@dataclass
class EnterpriseConfig:
    license_key: str = ""
    max_concurrent_analyses: int = 4
    siem_endpoint: str = ""
    siem_protocol: str = "syslog"
    rbac_enabled: bool = False


@dataclass
class Config:
    yara: YaraConfig = field(default_factory=YaraConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    api: APIConfig = field(default_factory=APIConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    case: CaseConfig = field(default_factory=CaseConfig)
    enterprise: EnterpriseConfig = field(default_factory=EnterpriseConfig)
    volatility_path: str = "vol"
    symbol_tables_dir: str = ""
    temp_dir: str = "/tmp/mfa"
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path) as f:
            data = json.load(f)
        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        cfg.threat_intel.virustotal_api_key = os.getenv("MFA_VT_API_KEY", "")
        cfg.threat_intel.abuseipdb_api_key = os.getenv("MFA_ABUSEIPDB_KEY", "")
        cfg.threat_intel.otx_api_key = os.getenv("MFA_OTX_KEY", "")
        cfg.api.api_key = os.getenv("MFA_API_KEY", "")
        cfg.api.ssl_certfile = os.getenv("MFA_SSL_CERT", "")
        cfg.api.ssl_keyfile = os.getenv("MFA_SSL_KEY", "")
        cfg.enterprise.license_key = os.getenv("MFA_LICENSE_KEY", "")
        cfg.enterprise.siem_endpoint = os.getenv("MFA_SIEM_ENDPOINT", "")
        cfg.log_level = os.getenv("MFA_LOG_LEVEL", "INFO")
        return cfg

    @classmethod
    def _from_dict(cls, data: dict) -> "Config":
        cfg = cls()
        for section_name, section_cls in [
            ("yara", YaraConfig), ("threat_intel", ThreatIntelConfig),
            ("report", ReportConfig), ("api", APIConfig),
            ("detection", DetectionConfig), ("case", CaseConfig),
            ("enterprise", EnterpriseConfig),
        ]:
            if section_name in data:
                setattr(cfg, section_name, section_cls(**data[section_name]))
        for key in ("volatility_path", "symbol_tables_dir", "temp_dir", "log_level"):
            if key in data:
                setattr(cfg, key, data[key])
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
