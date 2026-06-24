import struct
import re
import logging
from pathlib import Path
from typing import Optional
from .config import AnalysisProfile

logger = logging.getLogger(__name__)

WINDOWS_SIGNATURES = {
    b"MZ": "pe_header",
    b"RSDS": "pdb_debug",
}

KERNEL_PATTERNS = [
    (re.compile(rb"Windows\s+(\d+)\.\d+"), "windows"),
    (re.compile(rb"Microsoft Windows \[Version (\d+\.\d+\.\d+)"), "windows"),
    (re.compile(rb"Linux version (\d+\.\d+\.\d+)"), "linux"),
    (re.compile(rb"Darwin Kernel Version (\d+\.\d+\.\d+)"), "macos"),
    (re.compile(rb"FreeBSD (\d+\.\d+)"), "freebsd"),
]

WINDOWS_BUILD_MAP = {
    2600: ("Windows XP", "SP3"),
    3790: ("Windows Server 2003", ""),
    6000: ("Windows Vista", ""),
    6001: ("Windows Vista", "SP1"),
    6002: ("Windows Vista", "SP2"),
    7600: ("Windows 7", ""),
    7601: ("Windows 7", "SP1"),
    9200: ("Windows 8", ""),
    9600: ("Windows 8.1", ""),
    10240: ("Windows 10", "1507"),
    10586: ("Windows 10", "1511"),
    14393: ("Windows 10", "1607"),
    15063: ("Windows 10", "1703"),
    16299: ("Windows 10", "1709"),
    17134: ("Windows 10", "1803"),
    17763: ("Windows 10", "1809"),
    18362: ("Windows 10", "1903"),
    18363: ("Windows 10", "1909"),
    19041: ("Windows 10", "2004"),
    19042: ("Windows 10", "20H2"),
    19043: ("Windows 10", "21H1"),
    19044: ("Windows 10", "21H2"),
    19045: ("Windows 10", "22H2"),
    22000: ("Windows 11", "21H2"),
    22621: ("Windows 11", "22H2"),
    22631: ("Windows 11", "23H2"),
    26100: ("Windows 11", "24H2"),
}


class ProfileDetector:

    def detect(self, dump_path: str) -> AnalysisProfile:
        path = Path(dump_path)
        profile = AnalysisProfile()

        with open(path, "rb") as f:
            header = f.read(4096)
            profile.architecture = self._detect_architecture(f, header)
            profile.os_type = self._detect_os_type(f, header)
            if profile.os_type == "windows":
                self._detect_windows_details(f, profile)
            elif profile.os_type == "linux":
                self._detect_linux_details(f, profile)

        logger.info(
            "Detected profile: %s %s (%s)",
            profile.os_type, profile.os_version, profile.architecture,
        )
        return profile

    def _detect_architecture(self, f, header: bytes) -> str:
        f.seek(0)
        chunk = f.read(1024 * 1024)
        if b"PAGEDUMP" in chunk:
            return "x86"
        if b"PAGEDU64" in chunk:
            return "x64"

        pointer_count_64 = 0
        pointer_count_32 = 0
        for i in range(0, min(len(chunk), 4096), 8):
            val = int.from_bytes(chunk[i:i + 8], "little")
            if 0xFFFF800000000000 <= val <= 0xFFFFFFFFFFFFFFFF:
                pointer_count_64 += 1
            if 0x80000000 <= (val & 0xFFFFFFFF) <= 0xFFFFFFFF:
                pointer_count_32 += 1

        return "x64" if pointer_count_64 > pointer_count_32 else "x86"

    def _detect_os_type(self, f, header: bytes) -> str:
        f.seek(0)
        scan_size = min(64 * 1024 * 1024, f.seek(0, 2))
        f.seek(0)

        chunk_size = 4 * 1024 * 1024
        scanned = 0
        while scanned < scan_size:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            for pattern, os_type in KERNEL_PATTERNS:
                if pattern.search(chunk):
                    return os_type
            scanned += len(chunk)

        if b"KDBG" in header or b"MDMP" in header:
            return "windows"
        return "windows"

    def _detect_windows_details(self, f, profile: AnalysisProfile):
        f.seek(0)
        scan_size = min(32 * 1024 * 1024, f.seek(0, 2))
        f.seek(0)

        chunk_size = 4 * 1024 * 1024
        scanned = 0
        while scanned < scan_size:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            kdbg_offset = chunk.find(b"KDBG")
            if kdbg_offset >= 0:
                profile.kdbg = scanned + kdbg_offset
                logger.debug("Found KDBG at offset 0x%x", profile.kdbg)

            build_match = re.search(
                rb"(\d{4,5})\.\d+\.\w+\.\d+", chunk
            )
            if build_match:
                try:
                    build = int(build_match.group(1))
                    if build in WINDOWS_BUILD_MAP:
                        name, ver = WINDOWS_BUILD_MAP[build]
                        profile.os_version = f"{name} {ver}".strip()
                        profile.build_number = build
                except ValueError:
                    pass

            scanned += len(chunk)

        if not profile.os_version:
            profile.os_version = "Windows (version unknown)"

    def _detect_linux_details(self, f, profile: AnalysisProfile):
        f.seek(0)
        scan_size = min(32 * 1024 * 1024, f.seek(0, 2))
        f.seek(0)

        chunk_size = 4 * 1024 * 1024
        scanned = 0
        while scanned < scan_size:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            ver_match = re.search(
                rb"Linux version (\d+\.\d+\.\d+[^\s]*)\s+\(([^)]+)\)", chunk
            )
            if ver_match:
                profile.os_version = f"Linux {ver_match.group(1).decode('ascii', errors='replace')}"
                break

            scanned += len(chunk)

        if not profile.os_version:
            profile.os_version = "Linux (version unknown)"
