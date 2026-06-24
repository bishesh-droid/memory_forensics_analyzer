import json
import csv
import io
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ReportMetadata:
    case_id: str
    analyst: str
    company: str
    classification: str
    dump_path: str
    dump_hash: str
    os_profile: str
    generated_at: str
    tool_version: str


class ReportGenerator:

    VERSION = "1.0.0"

    def __init__(self, output_dir: str = "reports", analyst: str = "",
                 company: str = "", classification: str = "CONFIDENTIAL"):
        self._output_dir = output_dir
        self._analyst = analyst
        self._company = company
        self._classification = classification
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate_html(self, case_id: str, results: dict,
                      dump_info: dict = None) -> str:
        meta = self._build_metadata(case_id, dump_info)
        html = self._html_template(meta, results)
        path = Path(self._output_dir) / f"{case_id}_report.html"
        path.write_text(html)
        logger.info("Generated HTML report: %s", path)
        return str(path)

    def generate_json(self, case_id: str, results: dict,
                      dump_info: dict = None) -> str:
        meta = self._build_metadata(case_id, dump_info)
        report = {"metadata": meta.__dict__, "results": {}}
        for key, val in results.items():
            if hasattr(val, "to_dict"):
                report["results"][key] = val.to_dict()
            elif hasattr(val, "__dict__"):
                report["results"][key] = val.__dict__
            else:
                report["results"][key] = val
        path = Path(self._output_dir) / f"{case_id}_report.json"
        path.write_text(json.dumps(report, indent=2, default=str))
        logger.info("Generated JSON report: %s", path)
        return str(path)

    def generate_csv(self, case_id: str, results: dict) -> str:
        path = Path(self._output_dir) / f"{case_id}_report.csv"
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            for section, data in results.items():
                writer.writerow([f"=== {section} ==="])
                rows = data.rows if hasattr(data, "rows") else data.get("rows", [])
                if rows:
                    writer.writerow(rows[0].keys())
                    for row in rows:
                        writer.writerow(row.values())
                writer.writerow([])
        logger.info("Generated CSV report: %s", path)
        return str(path)

    def _build_metadata(self, case_id: str, dump_info: dict = None) -> ReportMetadata:
        info = dump_info or {}
        return ReportMetadata(
            case_id=case_id,
            analyst=self._analyst,
            company=self._company,
            classification=self._classification,
            dump_path=info.get("dump_path", ""),
            dump_hash=info.get("sha256", ""),
            os_profile=info.get("os_profile", ""),
            generated_at=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            tool_version=self.VERSION,
        )

    def _html_template(self, meta: ReportMetadata, results: dict) -> str:
        sections = []
        for key, val in results.items():
            rows = []
            if hasattr(val, "findings"):
                rows = [f.__dict__ if hasattr(f, "__dict__") else f for f in val.findings]
            elif hasattr(val, "rows"):
                rows = val.rows
            elif isinstance(val, dict) and "rows" in val:
                rows = val["rows"]
            elif isinstance(val, list):
                rows = [r.__dict__ if hasattr(r, "__dict__") else r for r in val]

            section_html = f'<h2>{key}</h2>\n'
            if rows:
                section_html += '<table>\n<thead><tr>'
                if isinstance(rows[0], dict):
                    headers = list(rows[0].keys())
                    section_html += "".join(f"<th>{h}</th>" for h in headers)
                    section_html += '</tr></thead>\n<tbody>\n'
                    for row in rows[:500]:
                        section_html += "<tr>"
                        for h in headers:
                            val_str = str(row.get(h, ""))[:200]
                            section_html += f"<td>{self._escape(val_str)}</td>"
                        section_html += "</tr>\n"
                    section_html += '</tbody></table>\n'
                    if len(rows) > 500:
                        section_html += f'<p><em>Showing 500 of {len(rows)} rows</em></p>\n'
            else:
                section_html += '<p>No data</p>\n'
            sections.append(section_html)

        return f'''<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Memory Forensics Report - {meta.case_id}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       max-width: 1400px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
h2 {{ color: #79c0ff; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 13px; }}
th {{ background: #161b22; color: #58a6ff; padding: 8px 12px; text-align: left;
      border: 1px solid #30363d; }}
td {{ padding: 6px 12px; border: 1px solid #21262d; word-break: break-all; max-width: 300px; }}
tr:nth-child(even) {{ background: #161b22; }}
tr:hover {{ background: #1c2128; }}
.meta {{ background: #161b22; padding: 15px; border-radius: 6px; margin: 15px 0; }}
.meta span {{ display: inline-block; margin-right: 30px; }}
.meta strong {{ color: #58a6ff; }}
.classification {{ text-align: center; color: #f85149; font-weight: bold;
                   padding: 5px; background: #21262d; margin: 5px 0; }}
</style>
</head><body>
<div class="classification">{meta.classification}</div>
<h1>Memory Forensics Analysis Report</h1>
<div class="meta">
<span><strong>Case ID:</strong> {meta.case_id}</span>
<span><strong>Analyst:</strong> {meta.analyst}</span>
<span><strong>Company:</strong> {meta.company}</span><br>
<span><strong>Dump:</strong> {meta.dump_path}</span>
<span><strong>SHA-256:</strong> {meta.dump_hash[:16]}...</span><br>
<span><strong>Profile:</strong> {meta.os_profile}</span>
<span><strong>Generated:</strong> {meta.generated_at}</span>
<span><strong>Tool:</strong> MFA v{meta.tool_version}</span>
</div>
{"".join(sections)}
<div class="classification">{meta.classification}</div>
</body></html>'''

    @staticmethod
    def _escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
