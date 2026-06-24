import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    source: str
    description: str
    pid: int
    process_name: str
    details: dict
    risk_score: float


class TimelineAnalyzer:

    def __init__(self):
        self._events: list[TimelineEvent] = []

    def build_timeline(self, analysis_results: dict) -> list:
        self._events.clear()
        for plugin, result in analysis_results.items():
            rows = result.rows if hasattr(result, "rows") else result.get("rows", [])
            if "pslist" in plugin.lower() or "psscan" in plugin.lower():
                self._extract_process_events(rows, plugin)
            elif "netscan" in plugin.lower() or "netstat" in plugin.lower():
                self._extract_network_events(rows, plugin)
            elif "filescan" in plugin.lower():
                self._extract_file_events(rows, plugin)
            elif "svcscan" in plugin.lower():
                self._extract_service_events(rows, plugin)

        self._events.sort(key=lambda e: e.timestamp if e.timestamp else "")
        logger.info("Built timeline with %d events", len(self._events))
        return self._events

    def _extract_process_events(self, rows: list, plugin: str):
        for row in rows:
            create_time = row.get("CreateTime", row.get("create_time", ""))
            exit_time = row.get("ExitTime", row.get("exit_time", ""))
            pid = row.get("PID", row.get("pid", 0))
            name = row.get("ImageFileName", row.get("name", "unknown"))
            ppid = row.get("PPID", row.get("ppid", 0))

            if create_time and create_time.strip() and create_time.strip() != "N/A":
                self._events.append(TimelineEvent(
                    timestamp=create_time.strip(),
                    event_type="process_create",
                    source=plugin,
                    description=f"Process created: {name} (PID {pid}, PPID {ppid})",
                    pid=int(pid) if str(pid).isdigit() else 0,
                    process_name=str(name),
                    details={"ppid": ppid, "action": "create"},
                    risk_score=0.0,
                ))

            if exit_time and exit_time.strip() and exit_time.strip() != "N/A":
                self._events.append(TimelineEvent(
                    timestamp=exit_time.strip(),
                    event_type="process_exit",
                    source=plugin,
                    description=f"Process exited: {name} (PID {pid})",
                    pid=int(pid) if str(pid).isdigit() else 0,
                    process_name=str(name),
                    details={"action": "exit"},
                    risk_score=0.0,
                ))

    def _extract_network_events(self, rows: list, plugin: str):
        for row in rows:
            created = row.get("Created", row.get("created", ""))
            pid = row.get("PID", row.get("pid", 0))
            owner = row.get("Owner", row.get("owner", "unknown"))
            local = row.get("LocalAddr", row.get("local_addr", ""))
            local_port = row.get("LocalPort", row.get("local_port", ""))
            foreign = row.get("ForeignAddr", row.get("foreign_addr", ""))
            foreign_port = row.get("ForeignPort", row.get("foreign_port", ""))
            state = row.get("State", row.get("state", ""))

            if created and created.strip() and created.strip() != "N/A":
                self._events.append(TimelineEvent(
                    timestamp=created.strip(),
                    event_type="network_connection",
                    source=plugin,
                    description=(
                        f"Network: {owner} ({local}:{local_port} -> "
                        f"{foreign}:{foreign_port}) [{state}]"
                    ),
                    pid=int(pid) if str(pid).isdigit() else 0,
                    process_name=str(owner),
                    details={
                        "local": f"{local}:{local_port}",
                        "remote": f"{foreign}:{foreign_port}",
                        "state": state,
                    },
                    risk_score=0.0,
                ))

    def _extract_file_events(self, rows: list, plugin: str):
        for row in rows:
            offset = row.get("Offset", row.get("offset", ""))
            name = row.get("Name", row.get("name", row.get("FileName", "")))
            if name:
                self._events.append(TimelineEvent(
                    timestamp="",
                    event_type="file_object",
                    source=plugin,
                    description=f"File object: {name}",
                    pid=0,
                    process_name="",
                    details={"offset": offset, "path": name},
                    risk_score=0.0,
                ))

    def _extract_service_events(self, rows: list, plugin: str):
        for row in rows:
            name = row.get("Name", row.get("name", ""))
            display = row.get("Display", row.get("display_name", ""))
            state = row.get("State", row.get("state", ""))
            binary = row.get("Binary", row.get("binary_path", ""))

            if name:
                self._events.append(TimelineEvent(
                    timestamp="",
                    event_type="service",
                    source=plugin,
                    description=f"Service: {name} ({display}) - {state}",
                    pid=0,
                    process_name="",
                    details={"state": state, "binary": binary, "display": display},
                    risk_score=0.0,
                ))

    def filter_by_type(self, event_type: str) -> list:
        return [e for e in self._events if e.event_type == event_type]

    def filter_by_time_range(self, start: str, end: str) -> list:
        return [
            e for e in self._events
            if e.timestamp and start <= e.timestamp <= end
        ]

    def get_suspicious_events(self, threshold: float = 0.5) -> list:
        return [e for e in self._events if e.risk_score >= threshold]

    def to_csv(self) -> str:
        lines = ["Timestamp,EventType,Source,PID,ProcessName,Description"]
        for e in self._events:
            desc = e.description.replace(",", ";").replace('"', "'")
            lines.append(
                f'"{e.timestamp}",{e.event_type},{e.source},'
                f'{e.pid},{e.process_name},"{desc}"'
            )
        return "\n".join(lines)
