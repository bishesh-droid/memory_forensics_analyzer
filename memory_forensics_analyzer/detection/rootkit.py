import logging
from dataclasses import dataclass, field
from typing import Optional
from ..core.engine import ForensicsEngine

logger = logging.getLogger(__name__)


@dataclass
class HiddenProcess:
    pid: int
    name: str
    ppid: int
    detection_method: str
    offset: str
    risk_score: float


@dataclass
class HookedFunction:
    table: str
    index: int
    function: str
    handler: str
    module: str
    is_hooked: bool
    risk_score: float


@dataclass
class HiddenModule:
    name: str
    base: str
    size: str
    path: str
    detection_method: str
    risk_score: float


@dataclass
class RootkitReport:
    hidden_processes: list
    hooked_functions: list
    hidden_modules: list
    suspicious_callbacks: list
    suspicious_drivers: list
    overall_risk: float
    findings_count: int


class RootkitDetector:

    def __init__(self, engine: ForensicsEngine):
        self._engine = engine

    def full_scan(self) -> RootkitReport:
        logger.info("Starting rootkit detection scan")
        hidden_procs = self._detect_hidden_processes()
        hooked_funcs = self._detect_ssdt_hooks()
        hidden_mods = self._detect_hidden_modules()
        callbacks = self._detect_suspicious_callbacks()
        drivers = self._detect_suspicious_drivers()

        total_findings = (
            len(hidden_procs) + len(hooked_funcs) + len(hidden_mods)
            + len(callbacks) + len(drivers)
        )
        risk = min(1.0, total_findings * 0.15)

        report = RootkitReport(
            hidden_processes=hidden_procs,
            hooked_functions=hooked_funcs,
            hidden_modules=hidden_mods,
            suspicious_callbacks=callbacks,
            suspicious_drivers=drivers,
            overall_risk=risk,
            findings_count=total_findings,
        )
        logger.info("Rootkit scan complete: %d findings, risk=%.2f", total_findings, risk)
        return report

    def _detect_hidden_processes(self) -> list:
        pslist_result = self._engine.run_plugin("windows.pslist.PsList")
        psscan_result = self._engine.run_plugin("windows.psscan.PsScan")

        pslist_pids = set()
        for row in pslist_result.rows:
            pid = row.get("PID", row.get("pid", ""))
            try:
                pslist_pids.add(int(pid))
            except (ValueError, TypeError):
                continue

        psscan_pids = {}
        for row in psscan_result.rows:
            pid = row.get("PID", row.get("pid", ""))
            try:
                pid_int = int(pid)
                psscan_pids[pid_int] = row
            except (ValueError, TypeError):
                continue

        hidden = []
        for pid, row in psscan_pids.items():
            if pid not in pslist_pids and pid != 0:
                hidden.append(HiddenProcess(
                    pid=pid,
                    name=row.get("ImageFileName", row.get("name", "unknown")),
                    ppid=int(row.get("PPID", row.get("ppid", 0))),
                    detection_method="DKOM (pslist vs psscan delta)",
                    offset=row.get("Offset", row.get("offset", "")),
                    risk_score=0.9,
                ))

        if hidden:
            logger.warning("Found %d hidden processes via DKOM detection", len(hidden))
        return hidden

    def _detect_ssdt_hooks(self) -> list:
        ssdt_result = self._engine.run_plugin("windows.ssdt.SSDT")
        hooked = []
        known_modules = {"ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe",
                         "win32k.sys", "win32kfull.sys", "win32kbase.sys"}

        for row in ssdt_result.rows:
            module = row.get("Module", row.get("module", ""))
            if module and module.lower() not in {m.lower() for m in known_modules}:
                hooked.append(HookedFunction(
                    table="SSDT",
                    index=int(row.get("Index", row.get("index", 0))),
                    function=row.get("Symbol", row.get("symbol", "")),
                    handler=row.get("Address", row.get("address", "")),
                    module=module,
                    is_hooked=True,
                    risk_score=0.85,
                ))

        if hooked:
            logger.warning("Found %d SSDT hooks", len(hooked))
        return hooked

    def _detect_hidden_modules(self) -> list:
        modscan_result = self._engine.run_plugin("windows.modscan.ModScan")
        modules_result = self._engine.run_plugin("windows.modules.Modules")

        listed_bases = set()
        for row in modules_result.rows:
            base = row.get("Base", row.get("base", ""))
            if base:
                listed_bases.add(base.lower())

        hidden = []
        for row in modscan_result.rows:
            base = row.get("Base", row.get("base", ""))
            if base and base.lower() not in listed_bases:
                hidden.append(HiddenModule(
                    name=row.get("File", row.get("name", "unknown")),
                    base=base,
                    size=row.get("Size", row.get("size", "")),
                    path=row.get("Path", row.get("path", "")),
                    detection_method="modscan vs modules delta",
                    risk_score=0.8,
                ))

        if hidden:
            logger.warning("Found %d hidden kernel modules", len(hidden))
        return hidden

    def _detect_suspicious_callbacks(self) -> list:
        result = self._engine.run_plugin("windows.callbacks.Callbacks")
        suspicious = []
        known_modules = {
            "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe",
            "ci.dll", "cng.sys", "ksecdd.sys", "tcpip.sys",
            "fltmgr.sys", "nt", "win32k.sys", "dxgkrnl.sys",
        }

        for row in result.rows:
            module = row.get("Module", row.get("module", ""))
            if module and module.lower() not in {m.lower() for m in known_modules}:
                suspicious.append({
                    "type": row.get("Type", row.get("type", "")),
                    "callback": row.get("Callback", row.get("callback", "")),
                    "module": module,
                    "detail": row.get("Detail", row.get("detail", "")),
                    "risk_score": 0.7,
                })

        return suspicious

    def _detect_suspicious_drivers(self) -> list:
        result = self._engine.run_plugin("windows.driverirp.DriverIrp")
        suspicious = []

        for row in result.rows:
            driver = row.get("DriverName", row.get("driver_name", ""))
            module = row.get("Module", row.get("module", ""))
            if not driver or not module:
                continue
            driver_base = driver.replace("\\Driver\\", "").lower()
            module_base = module.replace(".sys", "").lower()
            if driver_base != module_base and module.lower() not in ("ntoskrnl.exe",):
                suspicious.append({
                    "driver": driver,
                    "irp_function": row.get("IRP", row.get("irp", "")),
                    "handler_module": module,
                    "address": row.get("Address", row.get("address", "")),
                    "risk_score": 0.75,
                })

        return suspicious
