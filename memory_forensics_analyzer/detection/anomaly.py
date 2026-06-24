import logging
import math
from dataclasses import dataclass, field
from typing import Optional
from ..core.config import DetectionConfig

logger = logging.getLogger(__name__)


@dataclass
class ProcessAnomaly:
    pid: int
    name: str
    anomaly_type: str
    description: str
    expected: str
    actual: str
    risk_score: float
    mitre_id: str


@dataclass
class NetworkAnomaly:
    pid: int
    process: str
    anomaly_type: str
    local_addr: str
    remote_addr: str
    description: str
    risk_score: float


@dataclass
class AnomalyReport:
    process_anomalies: list
    network_anomalies: list
    module_anomalies: list
    overall_risk: float
    total_findings: int


EXPECTED_PARENTS = {
    "smss.exe": {"System", "smss.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "taskhost.exe": {"services.exe", "svchost.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "RuntimeBroker.exe": {"svchost.exe"},
    "spoolsv.exe": {"services.exe"},
    "SearchIndexer.exe": {"services.exe"},
}

EXPECTED_COUNTS = {
    "lsass.exe": (1, 1),
    "services.exe": (1, 1),
    "wininit.exe": (1, 1),
    "smss.exe": (1, 2),
    "csrss.exe": (1, 3),
    "winlogon.exe": (1, 3),
}

EXPECTED_SESSIONS = {
    "smss.exe": {0},
    "services.exe": {0},
    "lsass.exe": {0},
    "wininit.exe": {0},
    "csrss.exe": {0, 1},
}

SYSTEM_PROC_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "wininit.exe", "winlogon.exe", "explorer.exe",
    "System", "spoolsv.exe", "dwm.exe", "conhost.exe",
}

MASQUERADE_TARGETS = {
    "svchost.exe": ["scvhost.exe", "svch0st.exe", "svchosl.exe", "svchosts.exe"],
    "csrss.exe": ["csrs.exe", "cssrs.exe", "csrss .exe"],
    "lsass.exe": ["lsas.exe", "lsass .exe", "isass.exe", "lssas.exe"],
    "services.exe": ["servlces.exe", "service.exe"],
    "explorer.exe": ["explor3r.exe", "explore.exe", "explorar.exe"],
    "conhost.exe": ["conh0st.exe", "conhosts.exe"],
}


class AnomalyDetector:

    def __init__(self, config: DetectionConfig = None):
        self._config = config or DetectionConfig()

    def analyze(self, processes: list, connections: list = None,
                modules: list = None) -> AnomalyReport:
        logger.info("Starting anomaly detection on %d processes", len(processes))

        proc_anomalies = []
        proc_anomalies.extend(self._check_parent_relationships(processes))
        proc_anomalies.extend(self._check_process_counts(processes))
        proc_anomalies.extend(self._check_masquerading(processes))
        proc_anomalies.extend(self._check_session_ids(processes))
        proc_anomalies.extend(self._check_unusual_processes(processes))

        net_anomalies = []
        if connections:
            net_anomalies = self._check_network_anomalies(connections, processes)

        mod_anomalies = []
        if modules:
            mod_anomalies = self._check_module_anomalies(modules)

        total = len(proc_anomalies) + len(net_anomalies) + len(mod_anomalies)
        max_risk = 0.0
        for a in proc_anomalies:
            max_risk = max(max_risk, a.risk_score)
        for a in net_anomalies:
            max_risk = max(max_risk, a.risk_score)

        report = AnomalyReport(
            process_anomalies=proc_anomalies,
            network_anomalies=net_anomalies,
            module_anomalies=mod_anomalies,
            overall_risk=max_risk,
            total_findings=total,
        )
        logger.info("Anomaly detection: %d findings, max risk=%.2f", total, max_risk)
        return report

    def _check_parent_relationships(self, processes: list) -> list:
        anomalies = []
        pid_to_name = {}
        for p in processes:
            pid = str(p.get("PID", p.get("pid", "")))
            name = p.get("ImageFileName", p.get("name", ""))
            pid_to_name[pid] = name

        for p in processes:
            name = p.get("ImageFileName", p.get("name", "")).lower()
            ppid = str(p.get("PPID", p.get("ppid", "")))
            pid = p.get("PID", p.get("pid", ""))
            parent_name = pid_to_name.get(ppid, "unknown")

            for expected_name, expected_parents in EXPECTED_PARENTS.items():
                if name == expected_name.lower():
                    if parent_name not in expected_parents and parent_name != "unknown":
                        anomalies.append(ProcessAnomaly(
                            pid=int(pid), name=name,
                            anomaly_type="unexpected_parent",
                            description=f"{name} has unexpected parent {parent_name}",
                            expected=", ".join(expected_parents),
                            actual=parent_name,
                            risk_score=0.85,
                            mitre_id="T1036",
                        ))
                    break
        return anomalies

    def _check_process_counts(self, processes: list) -> list:
        anomalies = []
        name_counts = {}
        for p in processes:
            name = p.get("ImageFileName", p.get("name", "")).lower()
            name_counts[name] = name_counts.get(name, 0) + 1

        for proc_name, (min_count, max_count) in EXPECTED_COUNTS.items():
            count = name_counts.get(proc_name.lower(), 0)
            if count > max_count:
                anomalies.append(ProcessAnomaly(
                    pid=0, name=proc_name,
                    anomaly_type="excessive_instances",
                    description=f"{proc_name} has {count} instances (expected max {max_count})",
                    expected=f"{min_count}-{max_count}",
                    actual=str(count),
                    risk_score=0.75,
                    mitre_id="T1036.005",
                ))
        return anomalies

    def _check_masquerading(self, processes: list) -> list:
        anomalies = []
        all_targets = {}
        for legit, fakes in MASQUERADE_TARGETS.items():
            for fake in fakes:
                all_targets[fake.lower()] = legit

        for p in processes:
            name = p.get("ImageFileName", p.get("name", "")).lower()
            pid = p.get("PID", p.get("pid", 0))
            if name in all_targets:
                anomalies.append(ProcessAnomaly(
                    pid=int(pid), name=name,
                    anomaly_type="name_masquerading",
                    description=f"Process name '{name}' similar to legitimate '{all_targets[name]}'",
                    expected=all_targets[name],
                    actual=name,
                    risk_score=0.9,
                    mitre_id="T1036.005",
                ))

            for legit_name in SYSTEM_PROC_NAMES:
                if name != legit_name.lower() and self._levenshtein(name, legit_name.lower()) == 1:
                    if name not in all_targets:
                        anomalies.append(ProcessAnomaly(
                            pid=int(pid), name=name,
                            anomaly_type="name_masquerading",
                            description=f"'{name}' is 1 edit away from system process '{legit_name}'",
                            expected=legit_name,
                            actual=name,
                            risk_score=0.85,
                            mitre_id="T1036.005",
                        ))
        return anomalies

    def _check_session_ids(self, processes: list) -> list:
        anomalies = []
        for p in processes:
            name = p.get("ImageFileName", p.get("name", "")).lower()
            session = p.get("SessionId", p.get("session_id", ""))
            pid = p.get("PID", p.get("pid", 0))
            if name in {k.lower() for k in EXPECTED_SESSIONS}:
                expected = EXPECTED_SESSIONS.get(name, set())
                try:
                    sess_int = int(session)
                    if sess_int not in expected and session != "------":
                        anomalies.append(ProcessAnomaly(
                            pid=int(pid), name=name,
                            anomaly_type="wrong_session",
                            description=f"{name} in session {sess_int} (expected {expected})",
                            expected=str(expected),
                            actual=str(sess_int),
                            risk_score=0.6,
                            mitre_id="T1036",
                        ))
                except (ValueError, TypeError):
                    pass
        return anomalies

    def _check_unusual_processes(self, processes: list) -> list:
        anomalies = []
        suspicious_names = [
            "nc.exe", "ncat.exe", "netcat", "psexec",
            "mimikatz", "procdump", "lazagne",
            "bloodhound", "sharphound", "rubeus",
            "certutil", "bitsadmin", "mshta",
            "regsvr32", "rundll32", "wscript",
            "cscript", "powershell_ise",
        ]
        for p in processes:
            name = p.get("ImageFileName", p.get("name", "")).lower()
            pid = p.get("PID", p.get("pid", 0))
            for sus in suspicious_names:
                if sus in name:
                    anomalies.append(ProcessAnomaly(
                        pid=int(pid), name=name,
                        anomaly_type="suspicious_tool",
                        description=f"Known offensive/suspicious tool detected: {name}",
                        expected="No offensive tools",
                        actual=name,
                        risk_score=0.7,
                        mitre_id="T1588.002",
                    ))
                    break
        return anomalies

    def _check_network_anomalies(self, connections: list, processes: list) -> list:
        anomalies = []
        system_procs_no_outbound = {"lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"}

        pid_to_name = {}
        for p in processes:
            pid = str(p.get("PID", p.get("pid", "")))
            pid_to_name[pid] = p.get("ImageFileName", p.get("name", ""))

        for conn in connections:
            pid = str(conn.get("PID", conn.get("pid", "")))
            owner = conn.get("Owner", pid_to_name.get(pid, "unknown")).lower()
            remote = conn.get("ForeignAddr", conn.get("foreign_addr", ""))
            state = conn.get("State", conn.get("state", ""))

            if owner in system_procs_no_outbound and remote not in ("0.0.0.0", "*", "::"):
                if state in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
                    anomalies.append(NetworkAnomaly(
                        pid=int(pid) if pid.isdigit() else 0,
                        process=owner,
                        anomaly_type="unexpected_outbound",
                        local_addr=conn.get("LocalAddr", ""),
                        remote_addr=remote,
                        description=f"{owner} has outbound connection to {remote}",
                        risk_score=0.8,
                    ))

            remote_port = conn.get("ForeignPort", conn.get("foreign_port", ""))
            try:
                rp = int(remote_port)
                if rp in (4444, 5555, 1234, 8888, 9999, 31337, 6666, 6667):
                    anomalies.append(NetworkAnomaly(
                        pid=int(pid) if pid.isdigit() else 0,
                        process=owner,
                        anomaly_type="suspicious_port",
                        local_addr=conn.get("LocalAddr", ""),
                        remote_addr=f"{remote}:{remote_port}",
                        description=f"Connection to commonly used attack port {rp}",
                        risk_score=0.7,
                    ))
            except (ValueError, TypeError):
                pass
        return anomalies

    def _check_module_anomalies(self, modules: list) -> list:
        anomalies = []
        for mod in modules:
            path = mod.get("Path", mod.get("path", "")).lower()
            if path and ("temp" in path or "tmp" in path or "appdata" in path):
                anomalies.append({
                    "type": "suspicious_module_path",
                    "module": mod.get("File", mod.get("name", "")),
                    "path": path,
                    "risk_score": 0.65,
                })
        return anomalies

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return AnomalyDetector._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(
                    prev[j + 1] + 1,
                    curr[j] + 1,
                    prev[j] + (0 if c1 == c2 else 1),
                ))
            prev = curr
        return prev[-1]
