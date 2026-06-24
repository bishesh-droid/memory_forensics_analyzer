import logging
import os
import platform
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CaptureResult:
    success: bool
    dump_path: str
    file_size: int
    duration: float
    method: str
    error: str


class MemoryCapture:

    TOOLS = {
        "linux": ["avml", "lime", "fmem"],
        "windows": ["winpmem", "dumpit", "ramcapture"],
        "darwin": ["osxpmem"],
    }

    def __init__(self, output_dir: str = "captures"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._system = platform.system().lower()

    def capture(self, output_name: str = "", method: str = "") -> CaptureResult:
        if not output_name:
            output_name = f"memdump_{time.strftime('%Y%m%d_%H%M%S')}"

        if self._system == "linux":
            return self._capture_linux(output_name, method)
        elif self._system == "windows":
            return self._capture_windows(output_name, method)
        elif self._system == "darwin":
            return self._capture_macos(output_name, method)
        else:
            return CaptureResult(
                False, "", 0, 0, "", f"Unsupported platform: {self._system}"
            )

    def list_available_tools(self) -> list:
        available = []
        for tool in self.TOOLS.get(self._system, []):
            if self._tool_available(tool):
                available.append(tool)
        return available

    def _capture_linux(self, name: str, method: str) -> CaptureResult:
        output_path = str(self._output_dir / f"{name}.lime")
        start = time.time()

        if method == "avml" or (not method and self._tool_available("avml")):
            return self._run_capture(
                ["avml", output_path], output_path, start, "avml"
            )

        if method == "lime" or (not method and self._tool_available("insmod")):
            lime_ko = self._find_lime_module()
            if lime_ko:
                return self._run_capture(
                    ["insmod", lime_ko, f"path={output_path}", "format=lime"],
                    output_path, start, "lime",
                )

        if os.path.exists("/proc/kcore"):
            output_path = str(self._output_dir / f"{name}.raw")
            try:
                mem_size = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
                return self._run_capture(
                    ["dd", f"if=/proc/kcore", f"of={output_path}",
                     "bs=4M", f"count={mem_size // (4 * 1024 * 1024) + 1}"],
                    output_path, start, "proc_kcore",
                )
            except Exception as e:
                return CaptureResult(False, "", 0, time.time() - start, "proc_kcore", str(e))

        return CaptureResult(False, "", 0, 0, "",
                             "No capture tool found. Install avml or LiME.")

    def _capture_windows(self, name: str, method: str) -> CaptureResult:
        output_path = str(self._output_dir / f"{name}.raw")
        start = time.time()

        if method == "winpmem" or (not method and self._tool_available("winpmem")):
            return self._run_capture(
                ["winpmem", "-o", output_path], output_path, start, "winpmem"
            )

        if method == "dumpit" or (not method and self._tool_available("dumpit")):
            return self._run_capture(
                ["dumpit", "/OUTPUT", output_path, "/QUIET"],
                output_path, start, "dumpit",
            )

        return CaptureResult(False, "", 0, 0, "",
                             "No capture tool found. Install WinPmem or DumpIt.")

    def _capture_macos(self, name: str, method: str) -> CaptureResult:
        output_path = str(self._output_dir / f"{name}.raw")
        start = time.time()

        if self._tool_available("osxpmem"):
            return self._run_capture(
                ["osxpmem", "-o", output_path], output_path, start, "osxpmem"
            )

        return CaptureResult(False, "", 0, 0, "",
                             "No capture tool found. Install osxpmem.")

    def _run_capture(self, cmd: list, output_path: str,
                     start: float, method: str) -> CaptureResult:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            duration = time.time() - start
            path = Path(output_path)

            if path.exists() and path.stat().st_size > 0:
                logger.info(
                    "Memory captured via %s: %s (%.1f MB in %.1fs)",
                    method, output_path, path.stat().st_size / (1024 * 1024), duration,
                )
                return CaptureResult(
                    True, output_path, path.stat().st_size, duration, method, ""
                )
            else:
                return CaptureResult(
                    False, output_path, 0, duration, method,
                    result.stderr or "Capture produced empty file",
                )
        except subprocess.TimeoutExpired:
            return CaptureResult(
                False, output_path, 0, time.time() - start, method,
                "Capture timed out after 600s",
            )
        except Exception as e:
            return CaptureResult(
                False, output_path, 0, time.time() - start, method, str(e),
            )

    def _tool_available(self, tool: str) -> bool:
        try:
            subprocess.run(
                ["which", tool], capture_output=True, timeout=5
            )
            return True
        except Exception:
            return False

    def _find_lime_module(self) -> Optional[str]:
        search_paths = [
            "/lib/modules/",
            "/usr/lib/modules/",
            "/tmp/",
        ]
        kernel = platform.release()
        for base in search_paths:
            lime_path = Path(base) / kernel / "lime.ko"
            if lime_path.exists():
                return str(lime_path)
        for base in search_paths:
            for ko in Path(base).rglob("lime*.ko"):
                return str(ko)
        return None
