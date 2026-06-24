import json
import logging
import socket
import ssl
import time
import threading
from dataclasses import dataclass
from typing import Optional
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


@dataclass
class SIEMEvent:
    timestamp: str
    severity: str
    source: str
    event_type: str
    description: str
    details: dict
    case_id: str
    analyst: str


class SIEMConnector:

    def __init__(self, endpoint: str = "", protocol: str = "syslog",
                 facility: int = 1, port: int = 514, use_tls: bool = False):
        self._endpoint = endpoint
        self._protocol = protocol
        self._facility = facility
        self._port = port
        self._use_tls = use_tls
        self._queue: list[SIEMEvent] = []
        self._lock = threading.Lock()
        self._connected = False

    def send_event(self, event: SIEMEvent) -> bool:
        if not self._endpoint:
            logger.debug("No SIEM endpoint configured")
            return False

        if self._protocol == "syslog":
            return self._send_syslog(event)
        elif self._protocol == "http":
            return self._send_http(event)
        elif self._protocol == "cef":
            return self._send_cef(event)
        elif self._protocol == "leef":
            return self._send_leef(event)
        else:
            logger.error("Unknown SIEM protocol: %s", self._protocol)
            return False

    def send_finding(self, finding, case_id: str = "", analyst: str = ""):
        severity = "high"
        risk = getattr(finding, "risk_score", 0)
        if risk >= 0.8:
            severity = "critical"
        elif risk >= 0.6:
            severity = "high"
        elif risk >= 0.4:
            severity = "medium"
        else:
            severity = "low"

        event = SIEMEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            severity=severity,
            source="MFA",
            event_type=getattr(finding, "technique", "forensic_finding"),
            description=getattr(finding, "description", str(finding)),
            details=finding.__dict__ if hasattr(finding, "__dict__") else finding,
            case_id=case_id,
            analyst=analyst,
        )
        self.send_event(event)

    def send_bulk(self, events: list) -> int:
        sent = 0
        for event in events:
            if self.send_event(event):
                sent += 1
        return sent

    def _send_syslog(self, event: SIEMEvent) -> bool:
        severity_map = {"critical": 2, "high": 3, "medium": 4, "low": 6, "info": 6}
        sev = severity_map.get(event.severity, 6)
        priority = self._facility * 8 + sev

        msg = (
            f"<{priority}>1 {event.timestamp} MFA - - - "
            f"[mfa@1 severity=\"{event.severity}\" type=\"{event.event_type}\" "
            f"case=\"{event.case_id}\"] {event.description}"
        )

        try:
            host = self._endpoint.split(":")[0] if ":" in self._endpoint else self._endpoint
            port = int(self._endpoint.split(":")[1]) if ":" in self._endpoint else self._port

            if self._use_tls:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=10) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as sock:
                        sock.sendall(msg.encode("utf-8"))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(msg.encode("utf-8"), (host, port))
                sock.close()

            logger.debug("Sent syslog event to %s", self._endpoint)
            return True
        except Exception as e:
            logger.error("Syslog send failed: %s", e)
            return False

    def _send_http(self, event: SIEMEvent) -> bool:
        try:
            data = json.dumps({
                "timestamp": event.timestamp,
                "severity": event.severity,
                "source": event.source,
                "event_type": event.event_type,
                "description": event.description,
                "details": event.details if isinstance(event.details, dict) else str(event.details),
                "case_id": event.case_id,
                "analyst": event.analyst,
            }, default=str).encode()

            req = Request(
                self._endpoint,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status < 400
        except Exception as e:
            logger.error("HTTP SIEM send failed: %s", e)
            return False

    def _send_cef(self, event: SIEMEvent) -> bool:
        severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
        sev = severity_map.get(event.severity, 5)

        cef = (
            f"CEF:0|MemoryForensicsAnalyzer|MFA|1.0|{event.event_type}|"
            f"{event.description}|{sev}|"
            f"cs1={event.case_id} cs1Label=CaseID "
            f"suser={event.analyst} "
            f"msg={event.description}"
        )

        try:
            host = self._endpoint.split(":")[0]
            port = int(self._endpoint.split(":")[1]) if ":" in self._endpoint else self._port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(cef.encode(), (host, port))
            sock.close()
            return True
        except Exception as e:
            logger.error("CEF send failed: %s", e)
            return False

    def _send_leef(self, event: SIEMEvent) -> bool:
        leef = (
            f"LEEF:2.0|MemoryForensicsAnalyzer|MFA|1.0|{event.event_type}|"
            f"cat={event.event_type}\tsev={event.severity}\t"
            f"msg={event.description}\tcaseId={event.case_id}"
        )

        try:
            host = self._endpoint.split(":")[0]
            port = int(self._endpoint.split(":")[1]) if ":" in self._endpoint else self._port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(leef.encode(), (host, port))
            sock.close()
            return True
        except Exception as e:
            logger.error("LEEF send failed: %s", e)
            return False

    def test_connection(self) -> dict:
        test_event = SIEMEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            severity="info", source="MFA",
            event_type="connection_test",
            description="SIEM connectivity test from MFA",
            details={}, case_id="TEST", analyst="system",
        )
        success = self.send_event(test_event)
        return {
            "connected": success,
            "endpoint": self._endpoint,
            "protocol": self._protocol,
        }
