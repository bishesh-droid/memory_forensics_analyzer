import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    description: str
    detection: str
    url: str


TECHNIQUE_DB = {
    "T1055": MitreTechnique("T1055", "Process Injection", "Defense Evasion, Privilege Escalation",
        "Adversaries inject code into processes to evade defenses and elevate privileges.",
        "Monitor for anomalous memory allocations (RWX), unexpected DLL loads, CreateRemoteThread calls.",
        "https://attack.mitre.org/techniques/T1055/"),
    "T1055.001": MitreTechnique("T1055.001", "DLL Injection", "Defense Evasion",
        "Adversaries inject DLLs into process memory via CreateRemoteThread + LoadLibrary.",
        "Monitor for DLLs loaded from unusual paths, unexpected LoadLibrary calls.",
        "https://attack.mitre.org/techniques/T1055/001/"),
    "T1055.003": MitreTechnique("T1055.003", "Thread Execution Hijacking", "Defense Evasion",
        "Adversaries hijack existing threads to execute malicious code.",
        "Monitor for SuspendThread/SetThreadContext sequences.",
        "https://attack.mitre.org/techniques/T1055/003/"),
    "T1055.012": MitreTechnique("T1055.012", "Process Hollowing", "Defense Evasion",
        "Adversaries create a process in suspended state, replace its memory with malicious code.",
        "Compare in-memory PE headers with on-disk binaries, monitor for suspended process creation.",
        "https://attack.mitre.org/techniques/T1055/012/"),
    "T1036": MitreTechnique("T1036", "Masquerading", "Defense Evasion",
        "Adversaries use names of legitimate processes to evade detection.",
        "Check process names against known system process spelling and expected paths.",
        "https://attack.mitre.org/techniques/T1036/"),
    "T1036.005": MitreTechnique("T1036.005", "Match Legitimate Name or Location", "Defense Evasion",
        "Adversaries match the name or location of legitimate files to evade defenses.",
        "Verify process image paths match expected locations for system processes.",
        "https://attack.mitre.org/techniques/T1036/005/"),
    "T1014": MitreTechnique("T1014", "Rootkit", "Defense Evasion",
        "Adversaries use rootkits to hide system activity from tools and analysis.",
        "Cross-reference pslist vs psscan, check SSDT/IDT hooks, verify kernel module lists.",
        "https://attack.mitre.org/techniques/T1014/"),
    "T1547.001": MitreTechnique("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
        "Adversaries add Run key entries to execute programs at startup.",
        "Monitor HKLM/HKCU Run and RunOnce keys for unexpected entries.",
        "https://attack.mitre.org/techniques/T1547/001/"),
    "T1003": MitreTechnique("T1003", "OS Credential Dumping", "Credential Access",
        "Adversaries dump credentials from the OS to obtain account login information.",
        "Monitor for lsass.exe access, hashdump artifacts, mimikatz strings in memory.",
        "https://attack.mitre.org/techniques/T1003/"),
    "T1003.001": MitreTechnique("T1003.001", "LSASS Memory", "Credential Access",
        "Adversaries access LSASS process memory to extract credentials.",
        "Monitor for processes reading lsass.exe memory, MiniDumpWriteDump calls.",
        "https://attack.mitre.org/techniques/T1003/001/"),
    "T1071": MitreTechnique("T1071", "Application Layer Protocol", "Command and Control",
        "Adversaries use application layer protocols for C2 communication.",
        "Analyze network connections for unusual HTTP/DNS/SMTP traffic patterns.",
        "https://attack.mitre.org/techniques/T1071/"),
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution",
        "Adversaries abuse command and script interpreters to execute commands.",
        "Monitor process creation for cmd.exe, powershell.exe with suspicious arguments.",
        "https://attack.mitre.org/techniques/T1059/"),
    "T1059.001": MitreTechnique("T1059.001", "PowerShell", "Execution",
        "Adversaries use PowerShell to execute commands and scripts.",
        "Monitor for encoded commands, bypass flags, download cradles.",
        "https://attack.mitre.org/techniques/T1059/001/"),
    "T1543.003": MitreTechnique("T1543.003", "Windows Service", "Persistence, Privilege Escalation",
        "Adversaries create or modify Windows services for persistence.",
        "Monitor for new service creation, service binary path changes.",
        "https://attack.mitre.org/techniques/T1543/003/"),
    "T1574": MitreTechnique("T1574", "Hijack Execution Flow", "Defense Evasion, Persistence",
        "Adversaries hijack the way programs load code to execute malicious payloads.",
        "Monitor for DLL search order hijacking, PATH environment manipulation.",
        "https://attack.mitre.org/techniques/T1574/"),
    "T1588.002": MitreTechnique("T1588.002", "Obtain Capabilities: Tool", "Resource Development",
        "Adversaries obtain or develop tools for use during operations.",
        "Detect known offensive tools (mimikatz, cobalt strike, etc.) in memory.",
        "https://attack.mitre.org/techniques/T1588/002/"),
    "T1070": MitreTechnique("T1070", "Indicator Removal", "Defense Evasion",
        "Adversaries delete or modify artifacts to remove evidence.",
        "Look for log clearing, timestomping, file deletion patterns.",
        "https://attack.mitre.org/techniques/T1070/"),
    "T1027": MitreTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion",
        "Adversaries obfuscate payloads to hinder detection and analysis.",
        "High entropy memory regions, packed/encrypted code sections.",
        "https://attack.mitre.org/techniques/T1027/"),
    "T1569.002": MitreTechnique("T1569.002", "Service Execution", "Execution",
        "Adversaries abuse the service control manager to execute commands or payloads.",
        "Monitor for services with unusual binary paths or arguments.",
        "https://attack.mitre.org/techniques/T1569/002/"),
    "T1053": MitreTechnique("T1053", "Scheduled Task/Job", "Execution, Persistence",
        "Adversaries abuse task scheduling to execute malicious code.",
        "Check for suspicious scheduled tasks with unusual binaries.",
        "https://attack.mitre.org/techniques/T1053/"),
}


class MitreMapper:

    def __init__(self):
        self._techniques = dict(TECHNIQUE_DB)

    def get_technique(self, technique_id: str) -> MitreTechnique:
        return self._techniques.get(technique_id)

    def map_findings(self, findings: list) -> list:
        mapped = []
        for finding in findings:
            mitre_id = ""
            if hasattr(finding, "mitre_id"):
                mitre_id = finding.mitre_id
            elif isinstance(finding, dict):
                mitre_id = finding.get("mitre_id", "")

            if mitre_id and mitre_id in self._techniques:
                tech = self._techniques[mitre_id]
                mapped.append({
                    "finding": finding if isinstance(finding, dict) else finding.__dict__,
                    "technique": tech.__dict__,
                })
        return mapped

    def generate_attack_matrix(self, findings: list) -> dict:
        tactics = {}
        for finding in findings:
            mitre_id = getattr(finding, "mitre_id", "") or (
                finding.get("mitre_id", "") if isinstance(finding, dict) else ""
            )
            if mitre_id not in self._techniques:
                continue
            tech = self._techniques[mitre_id]
            for tactic in tech.tactic.split(", "):
                tactic = tactic.strip()
                if tactic not in tactics:
                    tactics[tactic] = []
                if tech.id not in [t["id"] for t in tactics[tactic]]:
                    tactics[tactic].append({
                        "id": tech.id,
                        "name": tech.name,
                        "count": 1,
                    })

        return tactics

    def get_detection_guidance(self, technique_ids: list) -> list:
        guidance = []
        for tid in technique_ids:
            tech = self._techniques.get(tid)
            if tech:
                guidance.append({
                    "technique": tech.id,
                    "name": tech.name,
                    "detection": tech.detection,
                    "reference": tech.url,
                })
        return guidance

    def all_techniques(self) -> list:
        return list(self._techniques.values())
