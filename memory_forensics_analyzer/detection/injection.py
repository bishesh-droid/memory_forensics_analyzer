import logging
import math
from dataclasses import dataclass
from typing import Optional
from ..core.engine import ForensicsEngine

logger = logging.getLogger(__name__)


@dataclass
class InjectionFinding:
    pid: int
    process_name: str
    technique: str
    vad_start: str
    vad_end: str
    protection: str
    data_preview: str
    entropy: float
    risk_score: float
    mitre_id: str
    description: str


@dataclass
class InjectionReport:
    findings: list
    processes_scanned: int
    suspicious_count: int
    critical_count: int


KNOWN_INJECTORS = {
    "VirtualAllocEx", "WriteProcessMemory", "NtWriteVirtualMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
    "QueueUserAPC", "NtQueueApcThread", "SetWindowsHookEx",
    "NtMapViewOfSection",
}


class InjectionDetector:

    def __init__(self, engine: ForensicsEngine, entropy_threshold: float = 7.0):
        self._engine = engine
        self._entropy_threshold = entropy_threshold

    def scan(self) -> InjectionReport:
        logger.info("Starting code injection scan")
        malfind_result = self._engine.run_plugin("windows.malfind.Malfind")
        pslist_result = self._engine.run_plugin("windows.pslist.PsList")
        dlllist_result = self._engine.run_plugin("windows.dlllist.DllList")

        findings = []

        for row in malfind_result.rows:
            finding = self._analyze_malfind_row(row)
            if finding:
                findings.append(finding)

        hollowing = self._detect_process_hollowing(pslist_result.rows, dlllist_result.rows)
        findings.extend(hollowing)

        dll_inject = self._detect_dll_injection(dlllist_result.rows)
        findings.extend(dll_inject)

        critical = sum(1 for f in findings if f.risk_score >= 0.8)
        report = InjectionReport(
            findings=findings,
            processes_scanned=len(pslist_result.rows),
            suspicious_count=len(findings),
            critical_count=critical,
        )
        logger.info(
            "Injection scan: %d findings (%d critical) across %d processes",
            len(findings), critical, report.processes_scanned,
        )
        return report

    def _analyze_malfind_row(self, row: dict) -> Optional[InjectionFinding]:
        protection = row.get("Protection", row.get("protection", ""))
        hexdump = row.get("Hexdump", row.get("hexdump", row.get("Disasm", "")))
        pid = int(row.get("PID", row.get("pid", 0)))
        name = row.get("Process", row.get("process", "unknown"))

        is_rwx = "EXECUTE" in protection.upper() and "WRITE" in protection.upper()
        has_mz = "4d 5a" in hexdump.lower() or "MZ" in hexdump

        entropy = self._calculate_hex_entropy(hexdump)
        technique = "Unknown injection"
        mitre_id = "T1055"

        if has_mz and is_rwx:
            technique = "Process hollowing / PE injection"
            mitre_id = "T1055.012"
            risk = 0.95
        elif is_rwx and entropy > self._entropy_threshold:
            technique = "Shellcode injection (high entropy RWX)"
            mitre_id = "T1055.001"
            risk = 0.85
        elif is_rwx:
            technique = "Suspicious RWX memory region"
            mitre_id = "T1055"
            risk = 0.6
        else:
            return None

        return InjectionFinding(
            pid=pid, process_name=name, technique=technique,
            vad_start=row.get("Start VPN", row.get("start", "")),
            vad_end=row.get("End VPN", row.get("end", "")),
            protection=protection,
            data_preview=hexdump[:128] if hexdump else "",
            entropy=entropy, risk_score=risk, mitre_id=mitre_id,
            description=f"{technique} detected in {name} (PID {pid})",
        )

    def _detect_process_hollowing(self, processes: list, dlls: list) -> list:
        findings = []
        system_procs = {
            "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
            "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
        }

        system_paths = {
            "svchost.exe": "\\windows\\system32\\svchost.exe",
            "csrss.exe": "\\windows\\system32\\csrss.exe",
            "lsass.exe": "\\windows\\system32\\lsass.exe",
            "services.exe": "\\windows\\system32\\services.exe",
            "smss.exe": "\\windows\\system32\\smss.exe",
            "wininit.exe": "\\windows\\system32\\wininit.exe",
            "winlogon.exe": "\\windows\\system32\\winlogon.exe",
            "explorer.exe": "\\windows\\explorer.exe",
        }

        pid_to_path = {}
        for dll_row in dlls:
            pid = dll_row.get("PID", dll_row.get("pid", ""))
            path = dll_row.get("Path", dll_row.get("path", ""))
            name = dll_row.get("Name", dll_row.get("name", ""))
            if path and name:
                pid_to_path.setdefault(str(pid), []).append(path.lower())

        for proc in processes:
            name = proc.get("ImageFileName", proc.get("name", "")).lower()
            pid = proc.get("PID", proc.get("pid", ""))
            if name not in system_procs:
                continue
            expected_path = system_paths.get(name, "")
            paths = pid_to_path.get(str(pid), [])
            if paths and expected_path:
                main_path = paths[0] if paths else ""
                if expected_path.lower() not in main_path:
                    findings.append(InjectionFinding(
                        pid=int(pid), process_name=name,
                        technique="Process hollowing (path mismatch)",
                        vad_start="", vad_end="",
                        protection="", data_preview="",
                        entropy=0.0, risk_score=0.9,
                        mitre_id="T1055.012",
                        description=(
                            f"{name} (PID {pid}) running from unexpected path: "
                            f"{main_path} (expected: {expected_path})"
                        ),
                    ))
        return findings

    def _detect_dll_injection(self, dlls: list) -> list:
        findings = []
        suspicious_dll_patterns = [
            "temp\\", "tmp\\", "appdata\\local\\temp",
            "downloads\\", "desktop\\", "public\\",
        ]
        suspicious_names = [
            "payload", "inject", "hook", "shell", "beacon",
            "metsrv", "stdapi",
        ]

        for row in dlls:
            path = row.get("Path", row.get("path", "")).lower()
            name = row.get("Name", row.get("name", "")).lower()
            pid = row.get("PID", row.get("pid", 0))
            proc = row.get("Process", row.get("process", "unknown"))

            for pattern in suspicious_dll_patterns:
                if pattern in path:
                    findings.append(InjectionFinding(
                        pid=int(pid), process_name=proc,
                        technique="Suspicious DLL load path",
                        vad_start="", vad_end="", protection="",
                        data_preview=path, entropy=0.0, risk_score=0.65,
                        mitre_id="T1055.001",
                        description=f"DLL loaded from suspicious path: {path}",
                    ))
                    break

            for sus_name in suspicious_names:
                if sus_name in name:
                    findings.append(InjectionFinding(
                        pid=int(pid), process_name=proc,
                        technique="Suspicious DLL name",
                        vad_start="", vad_end="", protection="",
                        data_preview=name, entropy=0.0, risk_score=0.7,
                        mitre_id="T1055.001",
                        description=f"Suspiciously named DLL: {name}",
                    ))
                    break
        return findings

    def _calculate_hex_entropy(self, hex_string: str) -> float:
        cleaned = hex_string.replace(" ", "").replace("\n", "")
        if len(cleaned) < 4:
            return 0.0
        try:
            data = bytes.fromhex(cleaned[:512])
        except ValueError:
            data = cleaned.encode()
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return entropy
