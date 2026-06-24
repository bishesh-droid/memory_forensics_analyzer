import logging
import os
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: list
    strings: list
    offset: int
    process_name: str
    pid: int
    meta: dict


@dataclass
class YaraScanResult:
    matches: list
    rules_loaded: int
    scan_duration: float
    errors: list


class YaraScanner:

    def __init__(self, rules_dir: str = "", timeout: int = 60):
        self._rules_dir = rules_dir
        self._timeout = timeout
        self._compiled_rules = None
        self._rule_count = 0

    def load_rules(self, rules_path: str = None) -> int:
        if not YARA_AVAILABLE:
            raise RuntimeError("yara-python not installed. Install with: pip install yara-python")

        path = rules_path or self._rules_dir
        if not path:
            self._compiled_rules = yara.compile(source=self._default_rules())
            self._rule_count = self._count_default_rules()
            return self._rule_count

        p = Path(path)
        if p.is_file():
            self._compiled_rules = yara.compile(filepath=str(p))
            self._rule_count = 1
        elif p.is_dir():
            sources = {}
            for rule_file in sorted(p.glob("**/*.yar")) + sorted(p.glob("**/*.yara")):
                ns = rule_file.stem
                sources[ns] = str(rule_file)
            if not sources:
                raise FileNotFoundError(f"No .yar/.yara files found in {path}")
            self._compiled_rules = yara.compile(filepaths=sources)
            self._rule_count = len(sources)
        else:
            raise FileNotFoundError(f"Rules path not found: {path}")

        logger.info("Loaded %d YARA rule files", self._rule_count)
        return self._rule_count

    def scan_file(self, dump_path: str) -> YaraScanResult:
        if not self._compiled_rules:
            self.load_rules()

        errors = []
        start = time.time()
        try:
            raw_matches = self._compiled_rules.match(
                dump_path, timeout=self._timeout
            )
        except yara.TimeoutError:
            return YaraScanResult([], self._rule_count, time.time() - start,
                                 ["Scan timed out"])
        except Exception as e:
            return YaraScanResult([], self._rule_count, time.time() - start,
                                 [str(e)])

        matches = []
        for m in raw_matches:
            string_hits = []
            for s in m.strings:
                for instance in s.instances:
                    string_hits.append({
                        "identifier": s.identifier,
                        "offset": instance.offset,
                        "data": instance.matched_data[:64].hex(),
                    })
            matches.append(YaraMatch(
                rule=m.rule,
                namespace=m.namespace,
                tags=list(m.tags),
                strings=string_hits,
                offset=string_hits[0]["offset"] if string_hits else 0,
                process_name="",
                pid=0,
                meta=dict(m.meta),
            ))

        duration = time.time() - start
        logger.info("YARA scan: %d matches in %.1fs", len(matches), duration)
        return YaraScanResult(matches, self._rule_count, duration, errors)

    def scan_buffer(self, data: bytes, pid: int = 0,
                    process_name: str = "") -> list:
        if not self._compiled_rules:
            self.load_rules()

        try:
            raw_matches = self._compiled_rules.match(data=data, timeout=self._timeout)
        except Exception:
            return []

        matches = []
        for m in raw_matches:
            string_hits = []
            for s in m.strings:
                for instance in s.instances:
                    string_hits.append({
                        "identifier": s.identifier,
                        "offset": instance.offset,
                        "data": instance.matched_data[:64].hex(),
                    })
            matches.append(YaraMatch(
                rule=m.rule, namespace=m.namespace,
                tags=list(m.tags), strings=string_hits,
                offset=string_hits[0]["offset"] if string_hits else 0,
                process_name=process_name, pid=pid,
                meta=dict(m.meta),
            ))
        return matches

    def _default_rules(self) -> str:
        return '''
rule Suspicious_MZ_Header {
    meta:
        description = "PE executable in unexpected memory region"
        severity = "medium"
    strings:
        $mz = { 4D 5A 90 00 }
    condition:
        $mz
}

rule Shellcode_Patterns {
    meta:
        description = "Common shellcode byte patterns"
        severity = "high"
    strings:
        $api_hash1 = { 64 A1 30 00 00 00 }
        $api_hash2 = { 64 8B 15 30 00 00 00 }
        $api_hash3 = { 65 48 8B 04 25 60 00 00 00 }
        $ws2 = "ws2_32" ascii nocase
        $wininet = "WinInet" ascii nocase
    condition:
        any of ($api_hash*) or (2 of ($ws2, $wininet))
}

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential harvesting tool"
        severity = "critical"
    strings:
        $s1 = "sekurlsa" ascii nocase
        $s2 = "kerberos" ascii nocase
        $s3 = "logonpasswords" ascii nocase
        $s4 = "wdigest" ascii nocase
        $s5 = "mimikatz" ascii nocase
    condition:
        3 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon indicators"
        severity = "critical"
    strings:
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "beacon.x64.dll" ascii
        $s4 = { 2E 2F 2E 2F 2E 2C }
        $cfg = "%02d/%02d/%02d %02d:%02d:%02d" ascii
    condition:
        2 of them
}

rule PowerShell_Encoded {
    meta:
        description = "Encoded PowerShell command"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand" ascii nocase
        $enc2 = "-enc " ascii nocase
        $enc3 = "FromBase64String" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
    condition:
        any of ($enc*) or ($bypass and $hidden)
}

rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload"
        severity = "critical"
    strings:
        $s1 = "metsrv" ascii
        $s2 = "stdapi" ascii
        $s3 = "priv" ascii
        $rev = { 6A 00 53 56 68 }
    condition:
        2 of ($s*) or $rev
}

rule Suspicious_Registry_Keys {
    meta:
        description = "Suspicious autorun registry paths"
        severity = "medium"
    strings:
        $r1 = "CurrentVersion\\Run" ascii nocase
        $r2 = "CurrentVersion\\RunOnce" ascii nocase
        $r3 = "Winlogon\\Shell" ascii nocase
        $r4 = "Image File Execution Options" ascii nocase
    condition:
        any of them
}
'''

    def _count_default_rules(self) -> int:
        return 7
