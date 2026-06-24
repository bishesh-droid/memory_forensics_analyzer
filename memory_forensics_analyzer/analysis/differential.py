import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from ..core.engine import ForensicsEngine

logger = logging.getLogger(__name__)


@dataclass
class DiffEntry:
    category: str
    change_type: str
    key: str
    before: dict
    after: dict
    risk_score: float
    description: str


@dataclass
class DifferentialReport:
    dump_before: str
    dump_after: str
    new_processes: list
    terminated_processes: list
    new_connections: list
    closed_connections: list
    new_modules: list
    removed_modules: list
    new_services: list
    changed_services: list
    all_changes: list
    summary: dict


class DifferentialAnalyzer:

    def __init__(self, config=None):
        self._config = config

    def compare(self, before_results: dict, after_results: dict,
                before_path: str = "", after_path: str = "") -> DifferentialReport:
        logger.info("Starting differential analysis")
        all_changes = []

        new_procs, term_procs = self._diff_processes(
            self._get_rows(before_results, "pslist", "PsList"),
            self._get_rows(after_results, "pslist", "PsList"),
        )
        all_changes.extend(new_procs + term_procs)

        new_conns, closed_conns = self._diff_connections(
            self._get_rows(before_results, "netscan", "NetScan"),
            self._get_rows(after_results, "netscan", "NetScan"),
        )
        all_changes.extend(new_conns + closed_conns)

        new_mods, removed_mods = self._diff_modules(
            self._get_rows(before_results, "modscan", "ModScan"),
            self._get_rows(after_results, "modscan", "ModScan"),
        )
        all_changes.extend(new_mods + removed_mods)

        new_svcs, changed_svcs = self._diff_services(
            self._get_rows(before_results, "svcscan", "SvcScan"),
            self._get_rows(after_results, "svcscan", "SvcScan"),
        )
        all_changes.extend(new_svcs + changed_svcs)

        summary = {
            "new_processes": len(new_procs),
            "terminated_processes": len(term_procs),
            "new_connections": len(new_conns),
            "closed_connections": len(closed_conns),
            "new_modules": len(new_mods),
            "removed_modules": len(removed_mods),
            "new_services": len(new_svcs),
            "changed_services": len(changed_svcs),
            "total_changes": len(all_changes),
            "max_risk": max((c.risk_score for c in all_changes), default=0.0),
        }

        report = DifferentialReport(
            dump_before=before_path, dump_after=after_path,
            new_processes=new_procs, terminated_processes=term_procs,
            new_connections=new_conns, closed_connections=closed_conns,
            new_modules=new_mods, removed_modules=removed_mods,
            new_services=new_svcs, changed_services=changed_svcs,
            all_changes=all_changes, summary=summary,
        )
        logger.info("Differential analysis: %d total changes", len(all_changes))
        return report

    def compare_dumps(self, before_path: str, after_path: str) -> DifferentialReport:
        engine_before = ForensicsEngine(self._config)
        engine_before.load_dump(before_path)
        plugins = [
            "windows.pslist.PsList", "windows.netscan.NetScan",
            "windows.modscan.ModScan", "windows.svcscan.SvcScan",
        ]
        before_results = engine_before.run_plugins(plugins)

        engine_after = ForensicsEngine(self._config)
        engine_after.load_dump(after_path)
        after_results = engine_after.run_plugins(plugins)

        return self.compare(before_results, after_results, before_path, after_path)

    def _get_rows(self, results: dict, *keys) -> list:
        for key in keys:
            for plugin_name, result in results.items():
                if key.lower() in plugin_name.lower():
                    if hasattr(result, "rows"):
                        return result.rows
                    return result.get("rows", [])
        return []

    def _diff_processes(self, before: list, after: list) -> tuple:
        before_pids = {
            self._proc_key(p): p for p in before
        }
        after_pids = {
            self._proc_key(p): p for p in after
        }

        new = []
        for key, proc in after_pids.items():
            if key not in before_pids:
                name = proc.get("ImageFileName", proc.get("name", "unknown"))
                new.append(DiffEntry(
                    category="process", change_type="new",
                    key=key, before={}, after=proc,
                    risk_score=0.5,
                    description=f"New process: {name} (PID {proc.get('PID', proc.get('pid', ''))})",
                ))

        terminated = []
        for key, proc in before_pids.items():
            if key not in after_pids:
                name = proc.get("ImageFileName", proc.get("name", "unknown"))
                terminated.append(DiffEntry(
                    category="process", change_type="terminated",
                    key=key, before=proc, after={},
                    risk_score=0.2,
                    description=f"Terminated: {name} (PID {proc.get('PID', proc.get('pid', ''))})",
                ))
        return new, terminated

    def _diff_connections(self, before: list, after: list) -> tuple:
        before_keys = {self._conn_key(c): c for c in before}
        after_keys = {self._conn_key(c): c for c in after}

        new = []
        for key, conn in after_keys.items():
            if key not in before_keys:
                new.append(DiffEntry(
                    category="connection", change_type="new",
                    key=key, before={}, after=conn,
                    risk_score=0.6,
                    description=f"New connection: {key}",
                ))

        closed = []
        for key, conn in before_keys.items():
            if key not in after_keys:
                closed.append(DiffEntry(
                    category="connection", change_type="closed",
                    key=key, before=conn, after={},
                    risk_score=0.1,
                    description=f"Closed connection: {key}",
                ))
        return new, closed

    def _diff_modules(self, before: list, after: list) -> tuple:
        before_keys = {self._mod_key(m): m for m in before}
        after_keys = {self._mod_key(m): m for m in after}

        new = []
        for key, mod in after_keys.items():
            if key not in before_keys:
                new.append(DiffEntry(
                    category="module", change_type="new",
                    key=key, before={}, after=mod,
                    risk_score=0.7,
                    description=f"New module loaded: {key}",
                ))

        removed = []
        for key, mod in before_keys.items():
            if key not in after_keys:
                removed.append(DiffEntry(
                    category="module", change_type="removed",
                    key=key, before=mod, after={},
                    risk_score=0.4,
                    description=f"Module unloaded: {key}",
                ))
        return new, removed

    def _diff_services(self, before: list, after: list) -> tuple:
        before_keys = {self._svc_key(s): s for s in before}
        after_keys = {self._svc_key(s): s for s in after}

        new = []
        for key, svc in after_keys.items():
            if key not in before_keys:
                new.append(DiffEntry(
                    category="service", change_type="new",
                    key=key, before={}, after=svc,
                    risk_score=0.7,
                    description=f"New service: {key}",
                ))

        changed = []
        for key in before_keys:
            if key in after_keys:
                b_state = before_keys[key].get("State", "")
                a_state = after_keys[key].get("State", "")
                if b_state != a_state:
                    changed.append(DiffEntry(
                        category="service", change_type="changed",
                        key=key, before=before_keys[key], after=after_keys[key],
                        risk_score=0.3,
                        description=f"Service {key} state: {b_state} -> {a_state}",
                    ))
        return new, changed

    def _proc_key(self, p: dict) -> str:
        pid = p.get("PID", p.get("pid", ""))
        name = p.get("ImageFileName", p.get("name", ""))
        return f"{name}:{pid}"

    def _conn_key(self, c: dict) -> str:
        local = c.get("LocalAddr", c.get("local_addr", ""))
        lport = c.get("LocalPort", c.get("local_port", ""))
        foreign = c.get("ForeignAddr", c.get("foreign_addr", ""))
        fport = c.get("ForeignPort", c.get("foreign_port", ""))
        proto = c.get("Proto", c.get("proto", ""))
        return f"{proto}:{local}:{lport}->{foreign}:{fport}"

    def _mod_key(self, m: dict) -> str:
        return m.get("File", m.get("name", m.get("Path", "")))

    def _svc_key(self, s: dict) -> str:
        return s.get("Name", s.get("name", ""))
