import json
import uuid
import time
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class STIXExporter:

    SPEC_VERSION = "2.1"

    def __init__(self, identity_name: str = "Memory Forensics Analyzer",
                 identity_id: str = ""):
        self._identity_name = identity_name
        self._identity_id = identity_id or f"identity--{uuid.uuid4()}"

    def export_iocs(self, ioc_report, case_id: str = "") -> dict:
        objects = [self._create_identity()]

        ioc_lists = [
            ("ip_addresses", "ipv4-addr"),
            ("domains", "domain-name"),
            ("urls", "url"),
            ("file_hashes", "file"),
            ("mutex_names", "mutex"),
            ("email_addresses", "email-addr"),
        ]

        for attr, stix_type in ioc_lists:
            iocs = getattr(ioc_report, attr, [])
            for ioc in iocs:
                indicator = self._create_indicator(ioc, stix_type)
                if indicator:
                    objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": self.SPEC_VERSION,
            "objects": objects,
        }
        return bundle

    def export_findings(self, findings: list, case_id: str = "") -> dict:
        objects = [self._create_identity()]

        for finding in findings:
            if hasattr(finding, "mitre_id") and finding.mitre_id:
                attack_pattern = self._create_attack_pattern(finding)
                indicator = self._create_finding_indicator(finding)
                if attack_pattern:
                    objects.append(attack_pattern)
                if indicator:
                    objects.append(indicator)
                    objects.append(self._create_relationship(
                        indicator["id"], attack_pattern["id"], "indicates"
                    ))

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": self.SPEC_VERSION,
            "objects": objects,
        }

    def save(self, bundle: dict, output_path: str):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(bundle, f, indent=2, default=str)
        logger.info("Exported STIX bundle to %s (%d objects)", output_path, len(bundle["objects"]))

    def _create_identity(self) -> dict:
        return {
            "type": "identity",
            "spec_version": self.SPEC_VERSION,
            "id": self._identity_id,
            "created": self._timestamp(),
            "modified": self._timestamp(),
            "name": self._identity_name,
            "identity_class": "system",
        }

    def _create_indicator(self, ioc, stix_type: str) -> Optional[dict]:
        value = ioc.value if hasattr(ioc, "value") else ioc.get("value", "")
        if not value:
            return None

        ioc_type = ioc.type if hasattr(ioc, "type") else ioc.get("type", "")
        confidence = ioc.confidence if hasattr(ioc, "confidence") else ioc.get("confidence", 0.5)

        if stix_type == "file":
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
        else:
            pattern = f"[{stix_type}:value = '{value}']"

        return {
            "type": "indicator",
            "spec_version": self.SPEC_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": self._timestamp(),
            "modified": self._timestamp(),
            "name": f"{ioc_type}: {value}",
            "pattern_type": "stix",
            "pattern": pattern,
            "valid_from": self._timestamp(),
            "confidence": int(confidence * 100),
            "created_by_ref": self._identity_id,
        }

    def _create_finding_indicator(self, finding) -> Optional[dict]:
        desc = getattr(finding, "description", "") or (
            finding.get("description", "") if isinstance(finding, dict) else ""
        )
        if not desc:
            return None
        return {
            "type": "indicator",
            "spec_version": self.SPEC_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": self._timestamp(),
            "modified": self._timestamp(),
            "name": desc[:256],
            "pattern_type": "stix",
            "pattern": f"[process:name = '{getattr(finding, 'process_name', 'unknown')}']",
            "valid_from": self._timestamp(),
            "confidence": int(getattr(finding, "risk_score", 0.5) * 100),
            "created_by_ref": self._identity_id,
        }

    def _create_attack_pattern(self, finding) -> Optional[dict]:
        mitre_id = getattr(finding, "mitre_id", "") or (
            finding.get("mitre_id", "") if isinstance(finding, dict) else ""
        )
        if not mitre_id:
            return None
        technique = getattr(finding, "technique", "") or (
            finding.get("technique", "") if isinstance(finding, dict) else mitre_id
        )
        return {
            "type": "attack-pattern",
            "spec_version": self.SPEC_VERSION,
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": self._timestamp(),
            "modified": self._timestamp(),
            "name": technique,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": mitre_id,
                "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
            }],
        }

    def _create_relationship(self, source_id: str, target_id: str,
                             rel_type: str) -> dict:
        return {
            "type": "relationship",
            "spec_version": self.SPEC_VERSION,
            "id": f"relationship--{uuid.uuid4()}",
            "created": self._timestamp(),
            "modified": self._timestamp(),
            "relationship_type": rel_type,
            "source_ref": source_id,
            "target_ref": target_id,
        }

    @staticmethod
    def _timestamp() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
