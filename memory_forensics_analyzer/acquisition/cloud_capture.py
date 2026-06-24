import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CloudCaptureResult:
    success: bool
    provider: str
    instance_id: str
    dump_path: str
    file_size: int
    duration: float
    error: str


class CloudCapture:

    def __init__(self, output_dir: str = "captures"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def capture_aws(self, instance_id: str, region: str = "",
                    profile: str = "") -> CloudCaptureResult:
        start = time.time()
        output_path = str(self._output_dir / f"aws_{instance_id}_{int(time.time())}.raw")

        cmd = ["aws", "ec2", "create-snapshot"]
        if region:
            cmd.extend(["--region", region])
        if profile:
            cmd.extend(["--profile", profile])

        try:
            list_cmd = [
                "aws", "ec2", "describe-volumes",
                "--filters", f"Name=attachment.instance-id,Values={instance_id}",
                "--query", "Volumes[0].VolumeId",
                "--output", "text",
            ]
            if region:
                list_cmd.extend(["--region", region])
            if profile:
                list_cmd.extend(["--profile", profile])

            result = subprocess.run(list_cmd, capture_output=True, text=True, timeout=30)
            volume_id = result.stdout.strip()

            if not volume_id or volume_id == "None":
                return CloudCaptureResult(
                    False, "aws", instance_id, "", 0, time.time() - start,
                    "No volume found for instance",
                )

            ssm_cmd = [
                "aws", "ssm", "send-command",
                "--instance-ids", instance_id,
                "--document-name", "AWS-RunShellScript",
                "--parameters",
                json.dumps({"commands": [
                    "apt-get install -y avml || yum install -y avml",
                    f"avml /tmp/memdump_{instance_id}.lime",
                    f"aws s3 cp /tmp/memdump_{instance_id}.lime s3://mfa-captures/",
                ]}),
            ]
            if region:
                ssm_cmd.extend(["--region", region])
            if profile:
                ssm_cmd.extend(["--profile", profile])

            result = subprocess.run(ssm_cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return CloudCaptureResult(
                    False, "aws", instance_id, "", 0, time.time() - start,
                    f"SSM command failed: {result.stderr}",
                )

            logger.info("AWS capture initiated for %s", instance_id)
            return CloudCaptureResult(
                True, "aws", instance_id, output_path, 0,
                time.time() - start, "",
            )
        except Exception as e:
            return CloudCaptureResult(
                False, "aws", instance_id, "", 0, time.time() - start, str(e),
            )

    def capture_azure(self, vm_name: str, resource_group: str) -> CloudCaptureResult:
        start = time.time()
        output_path = str(self._output_dir / f"azure_{vm_name}_{int(time.time())}.raw")

        try:
            cmd = [
                "az", "vm", "run-command", "invoke",
                "--resource-group", resource_group,
                "--name", vm_name,
                "--command-id", "RunShellScript",
                "--scripts",
                f"apt-get install -y avml && avml /tmp/memdump_{vm_name}.lime",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return CloudCaptureResult(
                    False, "azure", vm_name, "", 0, time.time() - start,
                    f"Azure command failed: {result.stderr}",
                )

            return CloudCaptureResult(
                True, "azure", vm_name, output_path, 0, time.time() - start, "",
            )
        except Exception as e:
            return CloudCaptureResult(
                False, "azure", vm_name, "", 0, time.time() - start, str(e),
            )

    def capture_gcp(self, instance_name: str, zone: str,
                    project: str = "") -> CloudCaptureResult:
        start = time.time()
        output_path = str(self._output_dir / f"gcp_{instance_name}_{int(time.time())}.raw")

        try:
            cmd = [
                "gcloud", "compute", "ssh", instance_name,
                "--zone", zone,
                "--command",
                f"sudo apt-get install -y avml && sudo avml /tmp/memdump.lime",
            ]
            if project:
                cmd.extend(["--project", project])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                return CloudCaptureResult(
                    False, "gcp", instance_name, "", 0, time.time() - start,
                    f"GCP command failed: {result.stderr}",
                )

            return CloudCaptureResult(
                True, "gcp", instance_name, output_path, 0, time.time() - start, "",
            )
        except Exception as e:
            return CloudCaptureResult(
                False, "gcp", instance_name, "", 0, time.time() - start, str(e),
            )

    def list_supported_providers(self) -> list:
        providers = []
        for tool, name in [("aws", "AWS"), ("az", "Azure"), ("gcloud", "GCP")]:
            try:
                subprocess.run(
                    [tool, "--version"], capture_output=True, timeout=5
                )
                providers.append(name)
            except Exception:
                pass
        return providers
