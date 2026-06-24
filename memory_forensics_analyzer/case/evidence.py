import hashlib
import json
import time
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class EvidenceRecord:
    evidence_id: str
    file_path: str
    original_name: str
    sha256: str
    md5: str
    file_size: int
    acquired_by: str
    acquired_at: str
    chain_of_custody: list
    notes: str


@dataclass
class CustodyEntry:
    action: str
    person: str
    timestamp: str
    reason: str
    location: str


class EvidenceTracker:

    def __init__(self, evidence_dir: str = "evidence"):
        self._evidence_dir = Path(evidence_dir)
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, EvidenceRecord] = {}
        self._manifest_path = self._evidence_dir / "manifest.json"
        self._load_manifest()

    def register(self, file_path: str, acquired_by: str = "",
                 notes: str = "") -> EvidenceRecord:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        sha256, md5 = self._hash_file(path)
        evidence_id = f"EV-{sha256[:12].upper()}"

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = EvidenceRecord(
            evidence_id=evidence_id,
            file_path=str(path.resolve()),
            original_name=path.name,
            sha256=sha256,
            md5=md5,
            file_size=path.stat().st_size,
            acquired_by=acquired_by,
            acquired_at=now,
            chain_of_custody=[asdict(CustodyEntry(
                action="registered",
                person=acquired_by,
                timestamp=now,
                reason="Initial evidence registration",
                location=str(path.resolve()),
            ))],
            notes=notes,
        )
        self._records[evidence_id] = record
        self._save_manifest()
        logger.info("Registered evidence %s: %s", evidence_id, path.name)
        return record

    def verify_integrity(self, evidence_id: str) -> dict:
        record = self._records.get(evidence_id)
        if not record:
            return {"valid": False, "error": "Evidence not found"}

        path = Path(record.file_path)
        if not path.exists():
            return {"valid": False, "error": "Evidence file missing"}

        current_sha256, current_md5 = self._hash_file(path)
        sha256_match = current_sha256 == record.sha256
        md5_match = current_md5 == record.md5
        size_match = path.stat().st_size == record.file_size

        return {
            "valid": sha256_match and md5_match and size_match,
            "evidence_id": evidence_id,
            "sha256_match": sha256_match,
            "md5_match": md5_match,
            "size_match": size_match,
            "original_sha256": record.sha256,
            "current_sha256": current_sha256,
        }

    def add_custody_entry(self, evidence_id: str, action: str,
                          person: str, reason: str = "",
                          location: str = "") -> bool:
        record = self._records.get(evidence_id)
        if not record:
            return False
        entry = CustodyEntry(
            action=action,
            person=person,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            reason=reason,
            location=location,
        )
        record.chain_of_custody.append(asdict(entry))
        self._save_manifest()
        return True

    def get_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._records.get(evidence_id)

    def list_evidence(self) -> list:
        return list(self._records.values())

    def get_custody_chain(self, evidence_id: str) -> list:
        record = self._records.get(evidence_id)
        return record.chain_of_custody if record else []

    def export_custody_report(self, evidence_id: str) -> str:
        record = self._records.get(evidence_id)
        if not record:
            return ""

        lines = [
            "CHAIN OF CUSTODY REPORT",
            "=" * 60,
            f"Evidence ID:    {record.evidence_id}",
            f"File:           {record.original_name}",
            f"SHA-256:        {record.sha256}",
            f"MD5:            {record.md5}",
            f"Size:           {record.file_size} bytes",
            f"Acquired By:    {record.acquired_by}",
            f"Acquired At:    {record.acquired_at}",
            "",
            "CUSTODY CHAIN:",
            "-" * 60,
        ]
        for entry in record.chain_of_custody:
            lines.append(
                f"  [{entry['timestamp']}] {entry['action']} by {entry['person']}"
                f" — {entry.get('reason', '')}"
            )
        lines.append("=" * 60)
        return "\n".join(lines)

    def _hash_file(self, path: Path) -> tuple:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()

    def _save_manifest(self):
        data = {}
        for eid, record in self._records.items():
            data[eid] = asdict(record)
        with open(self._manifest_path, "w") as f:
            json.dump(data, f, indent=2)

    def _load_manifest(self):
        if not self._manifest_path.exists():
            return
        try:
            with open(self._manifest_path) as f:
                data = json.load(f)
            for eid, record_data in data.items():
                self._records[eid] = EvidenceRecord(**record_data)
            logger.info("Loaded %d evidence records", len(self._records))
        except Exception as e:
            logger.warning("Failed to load evidence manifest: %s", e)
