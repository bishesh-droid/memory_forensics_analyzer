import hashlib
import hmac
import json
import time
import logging
import platform
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

SIGNING_KEY = b"mfa-license-signing-key-v1"


@dataclass
class License:
    key: str
    tier: str
    organization: str
    max_analysts: int
    max_dumps_per_day: int
    features: list
    issued_at: str
    expires_at: str
    hardware_id: str
    valid: bool


TIER_FEATURES = {
    "community": {
        "max_analysts": 1,
        "max_dumps": 5,
        "features": [
            "pslist", "netscan", "modscan", "dlllist", "cmdline",
            "process_tree", "timeline", "string_extraction",
            "basic_reporting",
        ],
    },
    "professional": {
        "max_analysts": 5,
        "max_dumps": 50,
        "features": [
            "pslist", "netscan", "modscan", "dlllist", "cmdline",
            "handles", "malfind", "ssdt", "callbacks", "filescan",
            "hashdump", "envars", "svcscan", "hivelist", "psscan",
            "process_tree", "timeline", "string_extraction",
            "yara_scanning", "rootkit_detection", "injection_detection",
            "anomaly_detection", "ioc_extraction",
            "differential_analysis", "threat_intel",
            "html_reporting", "json_reporting", "csv_reporting",
            "stix_export", "case_management", "api_access",
        ],
    },
    "enterprise": {
        "max_analysts": -1,
        "max_dumps": -1,
        "features": [
            "all",
            "rbac", "siem_integration", "distributed_analysis",
            "cloud_acquisition", "multi_tenant",
            "custom_yara", "priority_support",
        ],
    },
}


class LicenseManager:

    def __init__(self):
        self._license: Optional[License] = None

    def generate_key(self, tier: str, organization: str,
                     duration_days: int = 365) -> str:
        if tier not in TIER_FEATURES:
            raise ValueError(f"Unknown tier: {tier}")

        hw_id = self._get_hardware_id()
        issued = time.strftime("%Y-%m-%d", time.gmtime())
        expires = time.strftime(
            "%Y-%m-%d",
            time.gmtime(time.time() + duration_days * 86400),
        )

        payload = json.dumps({
            "tier": tier,
            "org": organization,
            "hw": hw_id,
            "issued": issued,
            "expires": expires,
        }, separators=(",", ":"))

        signature = hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]

        import base64
        encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        return f"MFA-{tier[0].upper()}-{encoded}-{signature}"

    def validate(self, license_key: str) -> License:
        try:
            parts = license_key.split("-", 2)
            if len(parts) < 3 or parts[0] != "MFA":
                return self._invalid("Invalid key format")

            body = parts[2]
            sig_sep = body.rfind("-")
            if sig_sep < 0:
                return self._invalid("Invalid key structure")

            encoded = body[:sig_sep]
            provided_sig = body[sig_sep + 1:]

            import base64
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            payload = base64.urlsafe_b64decode(encoded).decode()

            expected_sig = hmac.new(SIGNING_KEY, payload.encode(), hashlib.sha256).hexdigest()[:16]
            if not hmac.compare_digest(provided_sig, expected_sig):
                return self._invalid("Invalid signature")

            data = json.loads(payload)
            tier = data["tier"]
            tier_config = TIER_FEATURES.get(tier, {})

            hw_id = self._get_hardware_id()
            if data.get("hw") and data["hw"] != hw_id:
                logger.warning("Hardware ID mismatch")

            expires = data.get("expires", "")
            if expires and expires < time.strftime("%Y-%m-%d", time.gmtime()):
                return self._invalid("License expired")

            self._license = License(
                key=license_key, tier=tier,
                organization=data.get("org", ""),
                max_analysts=tier_config.get("max_analysts", 1),
                max_dumps_per_day=tier_config.get("max_dumps", 5),
                features=tier_config.get("features", []),
                issued_at=data.get("issued", ""),
                expires_at=expires,
                hardware_id=data.get("hw", ""),
                valid=True,
            )
            logger.info("License validated: %s tier for %s", tier, data.get("org", ""))
            return self._license

        except Exception as e:
            return self._invalid(f"Validation error: {e}")

    def check_feature(self, feature: str) -> bool:
        if not self._license or not self._license.valid:
            return feature in TIER_FEATURES["community"]["features"]
        if "all" in self._license.features:
            return True
        return feature in self._license.features

    def get_tier(self) -> str:
        if self._license and self._license.valid:
            return self._license.tier
        return "community"

    def get_limits(self) -> dict:
        tier = self.get_tier()
        config = TIER_FEATURES.get(tier, TIER_FEATURES["community"])
        return {
            "tier": tier,
            "max_analysts": config["max_analysts"],
            "max_dumps_per_day": config["max_dumps"],
            "features_count": len(config["features"]),
        }

    def _get_hardware_id(self) -> str:
        info = f"{platform.node()}:{platform.machine()}:{platform.system()}"
        return hashlib.sha256(info.encode()).hexdigest()[:16]

    def _invalid(self, reason: str) -> License:
        return License(
            key="", tier="community", organization="",
            max_analysts=1, max_dumps_per_day=5,
            features=TIER_FEATURES["community"]["features"],
            issued_at="", expires_at="", hardware_id="",
            valid=False,
        )
