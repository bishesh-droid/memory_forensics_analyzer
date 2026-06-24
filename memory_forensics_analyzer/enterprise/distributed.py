import json
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from ..core.engine import ForensicsEngine
from ..core.config import Config

logger = logging.getLogger(__name__)


@dataclass
class AnalysisJob:
    job_id: str
    dump_path: str
    status: str
    worker_id: str
    started_at: float
    completed_at: float
    results: dict
    error: str


class DistributedAnalyzer:

    def __init__(self, config: Config = None, max_workers: int = 4):
        self._config = config or Config.from_env()
        self._max_workers = max_workers
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max_workers)

    def submit_job(self, dump_path: str, plugins: list = None) -> str:
        import hashlib
        job_id = hashlib.sha256(
            f"{dump_path}:{time.time()}".encode()
        ).hexdigest()[:12]

        job = AnalysisJob(
            job_id=job_id,
            dump_path=dump_path,
            status="queued",
            worker_id="",
            started_at=0,
            completed_at=0,
            results={},
            error="",
        )
        with self._lock:
            self._jobs[job_id] = job

        self._pool.submit(self._execute_job, job_id, plugins)
        logger.info("Submitted job %s for %s", job_id, dump_path)
        return job_id

    def submit_batch(self, dump_paths: list, plugins: list = None) -> list:
        job_ids = []
        for path in dump_paths:
            job_id = self.submit_job(path, plugins)
            job_ids.append(job_id)
        logger.info("Submitted batch of %d jobs", len(job_ids))
        return job_ids

    def get_job_status(self, job_id: str) -> Optional[AnalysisJob]:
        return self._jobs.get(job_id)

    def list_jobs(self, status: str = None) -> list:
        with self._lock:
            jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return jobs

    def get_batch_progress(self, job_ids: list) -> dict:
        total = len(job_ids)
        completed = sum(1 for jid in job_ids if self._jobs.get(jid, AnalysisJob(
            "", "", "unknown", "", 0, 0, {}, ""
        )).status == "complete")
        failed = sum(1 for jid in job_ids if self._jobs.get(jid, AnalysisJob(
            "", "", "unknown", "", 0, 0, {}, ""
        )).status == "failed")
        running = sum(1 for jid in job_ids if self._jobs.get(jid, AnalysisJob(
            "", "", "unknown", "", 0, 0, {}, ""
        )).status == "running")

        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "queued": total - completed - failed - running,
            "progress_pct": (completed / total * 100) if total > 0 else 0,
        }

    def aggregate_results(self, job_ids: list) -> dict:
        all_results = {}
        for jid in job_ids:
            job = self._jobs.get(jid)
            if job and job.status == "complete":
                all_results[job.dump_path] = job.results
        return all_results

    def compare_dumps(self, job_ids: list) -> dict:
        from ..analysis.differential import DifferentialAnalyzer
        differ = DifferentialAnalyzer(self._config)
        comparisons = []

        completed_jobs = [
            self._jobs[jid] for jid in job_ids
            if jid in self._jobs and self._jobs[jid].status == "complete"
        ]

        for i in range(len(completed_jobs) - 1):
            before = completed_jobs[i]
            after = completed_jobs[i + 1]
            report = differ.compare(before.results, after.results,
                                    before.dump_path, after.dump_path)
            comparisons.append({
                "before": before.dump_path,
                "after": after.dump_path,
                "summary": report.summary,
            })
        return {"comparisons": comparisons}

    def shutdown(self):
        self._pool.shutdown(wait=True)
        logger.info("Distributed analyzer shut down")

    def _execute_job(self, job_id: str, plugins: list = None):
        job = self._jobs.get(job_id)
        if not job:
            return

        worker_id = threading.current_thread().name
        with self._lock:
            job.status = "running"
            job.worker_id = worker_id
            job.started_at = time.time()

        try:
            engine = ForensicsEngine(self._config)
            engine.load_dump(job.dump_path)

            if plugins:
                results = engine.run_plugins(plugins)
            else:
                results = engine.full_analysis()

            with self._lock:
                job.results = {k: v.to_dict() for k, v in results.items()}
                job.status = "complete"
                job.completed_at = time.time()

            duration = job.completed_at - job.started_at
            logger.info("Job %s completed in %.1fs", job_id, duration)

        except Exception as e:
            with self._lock:
                job.status = "failed"
                job.error = str(e)
                job.completed_at = time.time()
            logger.error("Job %s failed: %s", job_id, e)
