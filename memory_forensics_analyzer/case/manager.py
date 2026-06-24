import json
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CaseNote:
    id: str
    author: str
    timestamp: str
    content: str
    tags: list


@dataclass
class Case:
    id: str
    title: str
    description: str
    status: str
    priority: str
    analyst: str
    created_at: str
    updated_at: str
    dump_paths: list
    evidence_hashes: dict
    notes: list
    tags: list
    findings_summary: dict
    mitre_techniques: list


class CaseManager:

    def __init__(self, case_dir: str = "cases"):
        self._case_dir = Path(case_dir)
        self._case_dir.mkdir(parents=True, exist_ok=True)
        self._cases: dict[str, Case] = {}
        self._load_cases()

    def create_case(self, title: str, description: str = "",
                    analyst: str = "", priority: str = "medium") -> Case:
        case_id = f"MFA-{uuid.uuid4().hex[:8].upper()}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        case = Case(
            id=case_id, title=title, description=description,
            status="open", priority=priority, analyst=analyst,
            created_at=now, updated_at=now,
            dump_paths=[], evidence_hashes={},
            notes=[], tags=[], findings_summary={},
            mitre_techniques=[],
        )
        self._cases[case_id] = case
        self._save_case(case)
        logger.info("Created case %s: %s", case_id, title)
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        return self._cases.get(case_id)

    def list_cases(self, status: str = None) -> list:
        cases = list(self._cases.values())
        if status:
            cases = [c for c in cases if c.status == status]
        return sorted(cases, key=lambda c: c.updated_at, reverse=True)

    def update_case(self, case_id: str, **kwargs) -> Optional[Case]:
        case = self._cases.get(case_id)
        if not case:
            return None
        for key, val in kwargs.items():
            if hasattr(case, key):
                setattr(case, key, val)
        case.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save_case(case)
        return case

    def close_case(self, case_id: str) -> Optional[Case]:
        return self.update_case(case_id, status="closed")

    def add_note(self, case_id: str, content: str, author: str = "",
                 tags: list = None) -> Optional[CaseNote]:
        case = self._cases.get(case_id)
        if not case:
            return None
        note = CaseNote(
            id=str(uuid.uuid4())[:8],
            author=author,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            content=content,
            tags=tags or [],
        )
        case.notes.append(note)
        case.updated_at = note.timestamp
        self._save_case(case)
        return note

    def add_dump(self, case_id: str, dump_path: str, sha256: str = "") -> bool:
        case = self._cases.get(case_id)
        if not case:
            return False
        case.dump_paths.append(dump_path)
        if sha256:
            case.evidence_hashes[dump_path] = sha256
        case.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save_case(case)
        return True

    def add_findings(self, case_id: str, findings: dict):
        case = self._cases.get(case_id)
        if not case:
            return
        case.findings_summary.update(findings)
        case.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._save_case(case)

    def add_mitre_techniques(self, case_id: str, techniques: list):
        case = self._cases.get(case_id)
        if not case:
            return
        existing = set(case.mitre_techniques)
        for t in techniques:
            tid = t if isinstance(t, str) else t.get("id", "")
            if tid and tid not in existing:
                case.mitre_techniques.append(tid)
        self._save_case(case)

    def search(self, query: str) -> list:
        query = query.lower()
        return [
            c for c in self._cases.values()
            if query in c.title.lower()
            or query in c.description.lower()
            or any(query in n.content.lower() for n in c.notes)
            or any(query in t.lower() for t in c.tags)
        ]

    def _save_case(self, case: Case):
        path = self._case_dir / f"{case.id}.json"
        data = asdict(case)
        data["notes"] = [asdict(n) if hasattr(n, "__dict__") else n for n in case.notes]
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _load_cases(self):
        for path in self._case_dir.glob("MFA-*.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                notes = [
                    CaseNote(**n) if isinstance(n, dict) else n
                    for n in data.pop("notes", [])
                ]
                case = Case(**data, notes=notes)
                self._cases[case.id] = case
            except Exception as e:
                logger.warning("Failed to load case %s: %s", path, e)
        logger.info("Loaded %d cases", len(self._cases))
