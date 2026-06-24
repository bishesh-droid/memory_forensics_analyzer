import json
import time
import logging
import hashlib
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Depends
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from ..core.engine import ForensicsEngine
from ..core.config import Config


class RateLimiter:
    def __init__(self, max_requests: int = 60, window: int = 60):
        self._max = max_requests
        self._window = window
        self._clients: dict[str, list] = {}
        self._lock = threading.Lock()

    def check(self, client_ip: str) -> bool:
        now = time.time()
        with self._lock:
            timestamps = self._clients.get(client_ip, [])
            timestamps = [t for t in timestamps if now - t < self._window]
            if len(timestamps) >= self._max:
                return False
            timestamps.append(now)
            self._clients[client_ip] = timestamps
            return True


def create_app(config: Config = None) -> "FastAPI":
    if not FASTAPI_AVAILABLE:
        raise RuntimeError("FastAPI not installed. Install with: pip install fastapi uvicorn")

    cfg = config or Config.from_env()
    app = FastAPI(
        title="Memory Forensics Analyzer API",
        version="1.0.0",
        description="Production-grade memory forensics analysis API",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api.cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    limiter = RateLimiter()
    engines: dict[str, ForensicsEngine] = {}
    analyses: dict[str, dict] = {}

    def _get_api_key(request: Request) -> str:
        key = request.headers.get("X-API-Key", "")
        if cfg.api.api_key and key != cfg.api.api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return key

    @app.get("/health")
    def health():
        return {"status": "healthy", "version": "1.0.0", "timestamp": time.time()}

    @app.post("/analyze")
    async def start_analysis(request: Request, api_key: str = Depends(_get_api_key)):
        if not limiter.check(request.client.host):
            raise HTTPException(429, "Rate limit exceeded")

        body = await request.json()
        dump_path = body.get("dump_path", "")
        if not dump_path or not Path(dump_path).exists():
            raise HTTPException(400, "Invalid or missing dump_path")

        analysis_id = hashlib.sha256(
            f"{dump_path}:{time.time()}".encode()
        ).hexdigest()[:16]

        engine = ForensicsEngine(cfg)
        validation = engine.load_dump(dump_path)
        engines[analysis_id] = engine

        plugins = body.get("plugins", [])
        if not plugins:
            results = engine.full_analysis()
        else:
            results = engine.run_plugins(plugins)

        analyses[analysis_id] = {
            "id": analysis_id,
            "dump_path": dump_path,
            "status": "complete",
            "validation": validation.__dict__,
            "profile": engine.profile.__dict__,
            "results": {k: v.to_dict() for k, v in results.items()},
            "created_at": time.time(),
        }
        return analyses[analysis_id]

    @app.get("/analyses")
    def list_analyses(api_key: str = Depends(_get_api_key)):
        return [{
            "id": a["id"],
            "dump_path": a["dump_path"],
            "status": a["status"],
            "created_at": a["created_at"],
        } for a in analyses.values()]

    @app.get("/analyses/{analysis_id}")
    def get_analysis(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in analyses:
            raise HTTPException(404, "Analysis not found")
        return analyses[analysis_id]

    @app.post("/analyses/{analysis_id}/scan/yara")
    async def yara_scan(analysis_id: str, request: Request,
                        api_key: str = Depends(_get_api_key)):
        if analysis_id not in analyses:
            raise HTTPException(404, "Analysis not found")
        from ..detection.yara_scanner import YaraScanner
        body = await request.json()
        scanner = YaraScanner(rules_dir=body.get("rules_dir", ""))
        scanner.load_rules()
        result = scanner.scan_file(analyses[analysis_id]["dump_path"])
        return {
            "matches": [m.__dict__ for m in result.matches],
            "rules_loaded": result.rules_loaded,
            "duration": result.scan_duration,
        }

    @app.post("/analyses/{analysis_id}/scan/rootkit")
    def rootkit_scan(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in engines:
            raise HTTPException(404, "Analysis not found")
        from ..detection.rootkit import RootkitDetector
        detector = RootkitDetector(engines[analysis_id])
        report = detector.full_scan()
        return {
            "hidden_processes": [p.__dict__ for p in report.hidden_processes],
            "hooked_functions": [f.__dict__ for f in report.hooked_functions],
            "hidden_modules": [m.__dict__ for m in report.hidden_modules],
            "overall_risk": report.overall_risk,
            "findings_count": report.findings_count,
        }

    @app.post("/analyses/{analysis_id}/scan/injection")
    def injection_scan(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in engines:
            raise HTTPException(404, "Analysis not found")
        from ..detection.injection import InjectionDetector
        detector = InjectionDetector(engines[analysis_id])
        report = detector.scan()
        return {
            "findings": [f.__dict__ for f in report.findings],
            "processes_scanned": report.processes_scanned,
            "critical_count": report.critical_count,
        }

    @app.get("/analyses/{analysis_id}/timeline")
    def get_timeline(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in analyses:
            raise HTTPException(404, "Analysis not found")
        from ..analysis.timeline import TimelineAnalyzer
        analyzer = TimelineAnalyzer()
        engine = engines.get(analysis_id)
        if engine:
            events = analyzer.build_timeline(engine.all_results())
            return [e.__dict__ for e in events]
        return []

    @app.get("/analyses/{analysis_id}/process-tree")
    def get_process_tree(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in analyses:
            raise HTTPException(404, "Analysis not found")
        from ..analysis.process_tree import ProcessTreeBuilder
        builder = ProcessTreeBuilder()
        result = analyses[analysis_id].get("results", {})
        for key, data in result.items():
            if "pslist" in key.lower():
                roots = builder.build(data.get("rows", []))
                return {
                    "tree": builder.render_json(roots),
                    "stats": builder.get_statistics(),
                }
        return {"tree": [], "stats": {}}

    @app.get("/analyses/{analysis_id}/iocs")
    def get_iocs(analysis_id: str, api_key: str = Depends(_get_api_key)):
        if analysis_id not in engines:
            raise HTTPException(404, "Analysis not found")
        from ..detection.ioc_extractor import IOCExtractor
        extractor = IOCExtractor()
        report = extractor.extract_from_results(engines[analysis_id].all_results())
        return {
            "ip_addresses": [i.__dict__ for i in report.ip_addresses],
            "domains": [d.__dict__ for d in report.domains],
            "urls": [u.__dict__ for u in report.urls],
            "file_hashes": [h.__dict__ for h in report.file_hashes],
            "total_count": report.total_count,
        }

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard():
        return _dashboard_html(analyses)

    return app


def _dashboard_html(analyses: dict) -> str:
    rows = ""
    for a in sorted(analyses.values(), key=lambda x: x.get("created_at", 0), reverse=True):
        profile = a.get("profile", {})
        results = a.get("results", {})
        total_findings = sum(
            len(r.get("rows", [])) for r in results.values()
        )
        rows += f'''<tr>
            <td><a href="/analyses/{a['id']}">{a['id']}</a></td>
            <td>{Path(a.get('dump_path', '')).name}</td>
            <td>{profile.get('os_type', '')} {profile.get('os_version', '')}</td>
            <td>{a.get('status', '')}</td>
            <td>{total_findings}</td>
            <td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(a.get('created_at', 0)))}</td>
        </tr>'''

    return f'''<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>MFA Dashboard</title>
<meta http-equiv="refresh" content="10">
<style>
body {{ font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9;
       max-width: 1200px; margin: 0 auto; padding: 20px; }}
h1 {{ color: #58a6ff; }} a {{ color: #58a6ff; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: #161b22; color: #58a6ff; padding: 10px; text-align: left;
      border: 1px solid #30363d; }}
td {{ padding: 8px 10px; border: 1px solid #21262d; }}
tr:hover {{ background: #1c2128; }}
.stat {{ display: inline-block; background: #161b22; padding: 15px 25px;
         border-radius: 8px; margin: 5px; text-align: center; }}
.stat .num {{ font-size: 28px; color: #58a6ff; font-weight: bold; }}
.stat .label {{ font-size: 12px; color: #8b949e; }}
</style>
</head><body>
<h1>Memory Forensics Analyzer Dashboard</h1>
<div>
<div class="stat"><div class="num">{len(analyses)}</div><div class="label">Total Analyses</div></div>
<div class="stat"><div class="num">{sum(1 for a in analyses.values() if a.get('status')=='complete')}</div>
<div class="label">Completed</div></div>
</div>
<h2>Recent Analyses</h2>
<table><thead><tr><th>ID</th><th>Dump</th><th>OS</th><th>Status</th><th>Findings</th>
<th>Date</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>'''
