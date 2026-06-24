import logging
import subprocess
import json
import os
import time
from pathlib import Path
from typing import Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import Config, AnalysisProfile
from .validator import DumpValidator, ValidationResult
from .profile import ProfileDetector

logger = logging.getLogger(__name__)


class VolatilityBackend:

    def __init__(self, config: Config):
        self._vol_path = config.volatility_path
        self._symbol_dir = config.symbol_tables_dir
        self._timeout = 300

    def run(self, dump_path: str, plugin: str, extra_args: list = None) -> dict:
        cmd = [self._vol_path, "-f", dump_path, "-r", "json", plugin]
        if self._symbol_dir:
            cmd.extend(["--symbol-dirs", self._symbol_dir])
        if extra_args:
            cmd.extend(extra_args)

        logger.debug("Running: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._timeout, check=False,
            )
            if result.returncode != 0:
                logger.warning("Plugin %s returned %d: %s", plugin, result.returncode, result.stderr[:500])
                return self._parse_text_output(result.stdout, plugin)
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return self._parse_text_output(result.stdout, plugin)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Plugin {plugin} timed out after {self._timeout}s")
        except FileNotFoundError:
            raise RuntimeError(
                f"Volatility not found at '{self._vol_path}'. "
                "Install with: pip install volatility3"
            )

    def _parse_text_output(self, output: str, plugin: str) -> dict:
        lines = output.strip().split("\n")
        if len(lines) < 2:
            return {"rows": [], "columns": []}

        header = lines[0]
        columns = [c.strip() for c in header.split("\t")] if "\t" in header else header.split()
        rows = []
        for line in lines[1:]:
            if line.startswith("---") or not line.strip():
                continue
            if "\t" in line:
                values = [v.strip() for v in line.split("\t")]
            else:
                values = line.split()
            row = {}
            for i, col in enumerate(columns):
                row[col] = values[i] if i < len(values) else ""
            rows.append(row)
        return {"rows": rows, "columns": columns}

    def available_plugins(self) -> list:
        try:
            result = subprocess.run(
                [self._vol_path, "--help"], capture_output=True, text=True, timeout=30,
            )
            plugins = []
            in_plugins = False
            for line in result.stdout.split("\n"):
                if "Plugins" in line:
                    in_plugins = True
                    continue
                if in_plugins and line.strip() and not line.startswith(" " * 4):
                    in_plugins = False
                if in_plugins and line.strip():
                    name = line.strip().split()[0]
                    plugins.append(name)
            return plugins
        except Exception:
            return []


class AnalysisResult:

    def __init__(self, plugin: str, data: dict, duration: float):
        self.plugin = plugin
        self.data = data
        self.duration = duration
        self.timestamp = time.time()
        self.rows = data.get("rows", [])
        self.columns = data.get("columns", [])
        self.error: Optional[str] = None

    @property
    def count(self) -> int:
        return len(self.rows)

    def to_dict(self) -> dict:
        return {
            "plugin": self.plugin,
            "count": self.count,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "columns": self.columns,
            "rows": self.rows,
            "error": self.error,
        }


class ForensicsEngine:

    def __init__(self, config: Config = None):
        self.config = config or Config.from_env()
        self._backend = VolatilityBackend(self.config)
        self._validator = DumpValidator()
        self._profiler = ProfileDetector()
        self._results: dict[str, AnalysisResult] = {}
        self._dump_path: Optional[str] = None
        self._profile: Optional[AnalysisProfile] = None
        self._validation: Optional[ValidationResult] = None

    def load_dump(self, path: str) -> ValidationResult:
        self._validation = self._validator.validate(path)
        if not self._validation.valid:
            raise ValueError(
                f"Invalid memory dump: {'; '.join(self._validation.errors)}"
            )
        self._dump_path = path
        self._profile = self._profiler.detect(path)
        logger.info(
            "Loaded dump: %s (%s, %s, %.1f MB)",
            path, self._profile.os_type, self._profile.architecture,
            self._validation.file_size / (1024 * 1024),
        )
        return self._validation

    @property
    def profile(self) -> Optional[AnalysisProfile]:
        return self._profile

    @property
    def validation(self) -> Optional[ValidationResult]:
        return self._validation

    def run_plugin(self, plugin: str, extra_args: list = None) -> AnalysisResult:
        if not self._dump_path:
            raise RuntimeError("No memory dump loaded. Call load_dump() first.")
        start = time.time()
        try:
            data = self._backend.run(self._dump_path, plugin, extra_args)
            result = AnalysisResult(plugin, data, time.time() - start)
        except Exception as e:
            result = AnalysisResult(plugin, {"rows": [], "columns": []}, time.time() - start)
            result.error = str(e)
            logger.error("Plugin %s failed: %s", plugin, e)
        self._results[plugin] = result
        return result

    def run_plugins(self, plugins: list, max_workers: int = 4) -> dict:
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self.run_plugin, p): p for p in plugins
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    results[plugin] = future.result()
                except Exception as e:
                    logger.error("Plugin %s raised: %s", plugin, e)
        return results

    def full_analysis(self) -> dict:
        plugins = self._get_os_plugins()
        return self.run_plugins(plugins)

    def _get_os_plugins(self) -> list:
        if not self._profile:
            return []
        if self._profile.os_type == "windows":
            return [
                "windows.pslist.PsList",
                "windows.psscan.PsScan",
                "windows.netscan.NetScan",
                "windows.dlllist.DllList",
                "windows.handles.Handles",
                "windows.cmdline.CmdLine",
                "windows.modscan.ModScan",
                "windows.svcscan.SvcScan",
                "windows.malfind.Malfind",
                "windows.ssdt.SSDT",
                "windows.callbacks.Callbacks",
                "windows.driverirp.DriverIrp",
                "windows.filescan.FileScan",
                "windows.envars.Envars",
                "windows.registry.hivelist.HiveList",
            ]
        elif self._profile.os_type == "linux":
            return [
                "linux.pslist.PsList",
                "linux.pstree.PsTree",
                "linux.lsmod.Lsmod",
                "linux.sockstat.Sockstat",
                "linux.bash.Bash",
                "linux.elfs.Elfs",
                "linux.proc.Maps",
                "linux.check_idt.Check_idt",
                "linux.check_syscall.Check_syscall",
            ]
        elif self._profile.os_type == "macos":
            return [
                "mac.pslist.PsList",
                "mac.pstree.PsTree",
                "mac.lsmod.Lsmod",
                "mac.netstat.Netstat",
                "mac.bash.Bash",
            ]
        return []

    def get_result(self, plugin: str) -> Optional[AnalysisResult]:
        return self._results.get(plugin)

    def all_results(self) -> dict:
        return dict(self._results)

    def export_results(self, path: str, fmt: str = "json"):
        data = {k: v.to_dict() for k, v in self._results.items()}
        data["metadata"] = {
            "dump_path": self._dump_path,
            "profile": self._profile.__dict__ if self._profile else None,
            "validation": self._validation.__dict__ if self._validation else None,
        }
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
