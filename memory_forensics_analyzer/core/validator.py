import hashlib
import struct
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    valid: bool
    file_path: str
    file_size: int
    sha256: str
    md5: str
    format_detected: str
    errors: list
    warnings: list


SIGNATURES = {
    b"MDMP": "windows_minidump",
    b"PAGEDU64": "windows_crash_64",
    b"PAGEDUMP": "windows_crash_32",
    b"EMiL": "elf_core",
    b"\x7fELF": "elf_core",
    b"KDMP": "windows_kernel_dump",
    b"HIBR": "windows_hibernation",
    b"RIFF": "lime_format",
    b"ElfCor": "vmware_vmss",
}

VMWARE_MAGIC = b"\xd2\xbe\xd2\xbe"
QEMU_MAGIC = b"QEVM"


class DumpValidator:

    def validate(self, file_path: str) -> ValidationResult:
        path = Path(file_path)
        errors = []
        warnings = []

        if not path.exists():
            return ValidationResult(
                valid=False, file_path=file_path, file_size=0,
                sha256="", md5="", format_detected="unknown",
                errors=["File does not exist"], warnings=[],
            )

        if not path.is_file():
            return ValidationResult(
                valid=False, file_path=file_path, file_size=0,
                sha256="", md5="", format_detected="unknown",
                errors=["Path is not a file"], warnings=[],
            )

        file_size = path.stat().st_size

        if file_size == 0:
            return ValidationResult(
                valid=False, file_path=file_path, file_size=0,
                sha256="", md5="", format_detected="unknown",
                errors=["File is empty"], warnings=[],
            )

        if file_size < 1024:
            errors.append(f"File too small ({file_size} bytes) to be a valid memory dump")

        if file_size < 64 * 1024 * 1024:
            warnings.append("File is under 64MB — may be a partial dump")

        fmt = self._detect_format(path)

        sha256, md5 = self._compute_hashes(path)

        if self._check_corruption(path):
            warnings.append("Potential corruption detected: large zero-filled regions")

        valid = len(errors) == 0
        return ValidationResult(
            valid=valid, file_path=file_path, file_size=file_size,
            sha256=sha256, md5=md5, format_detected=fmt,
            errors=errors, warnings=warnings,
        )

    def _detect_format(self, path: Path) -> str:
        with open(path, "rb") as f:
            header = f.read(4096)

        for sig, fmt in SIGNATURES.items():
            if header[:len(sig)] == sig:
                return fmt

        if VMWARE_MAGIC in header[:64]:
            return "vmware_snapshot"
        if QEMU_MAGIC in header[:64]:
            return "qemu_snapshot"

        ext = path.suffix.lower()
        format_map = {
            ".vmem": "vmware_vmem",
            ".raw": "raw_dump",
            ".mem": "raw_dump",
            ".dmp": "windows_dump",
            ".lime": "lime_format",
            ".aff4": "aff4_format",
            ".dd": "dd_image",
        }
        return format_map.get(ext, "raw_dump")

    def _compute_hashes(self, path: Path, chunk_size: int = 8192) -> tuple:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()

    def _check_corruption(self, path: Path) -> bool:
        zero_block = b"\x00" * 4096
        consecutive_zeros = 0
        threshold = 10
        with open(path, "rb") as f:
            while True:
                block = f.read(4096)
                if not block:
                    break
                if block == zero_block:
                    consecutive_zeros += 1
                    if consecutive_zeros >= threshold:
                        return True
                else:
                    consecutive_zeros = 0
        return False
