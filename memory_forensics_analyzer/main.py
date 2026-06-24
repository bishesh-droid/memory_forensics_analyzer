import argparse
import json
import logging
import sys
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Memory Forensics Analyzer — Production-grade memory forensics platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    analyze_p = sub.add_parser("analyze", help="Run full analysis on a memory dump")
    analyze_p.add_argument("-f", "--file", required=True, help="Path to memory dump")
    analyze_p.add_argument("-p", "--plugins", nargs="*", help="Specific plugins to run")
    analyze_p.add_argument("-o", "--output", default="", help="Output file path")
    analyze_p.add_argument("--format", choices=["json", "html", "csv"], default="json")
    analyze_p.add_argument("--max-workers", type=int, default=4)

    scan_p = sub.add_parser("scan", help="Run detection scans")
    scan_p.add_argument("-f", "--file", required=True, help="Path to memory dump")
    scan_p.add_argument("--yara", action="store_true", help="Run YARA scan")
    scan_p.add_argument("--rootkit", action="store_true", help="Run rootkit detection")
    scan_p.add_argument("--injection", action="store_true", help="Run injection detection")
    scan_p.add_argument("--anomaly", action="store_true", help="Run anomaly detection")
    scan_p.add_argument("--ioc", action="store_true", help="Extract IOCs")
    scan_p.add_argument("--all", action="store_true", help="Run all scans")
    scan_p.add_argument("--yara-rules", default="", help="Path to YARA rules")
    scan_p.add_argument("-o", "--output", default="", help="Output file path")

    timeline_p = sub.add_parser("timeline", help="Build event timeline")
    timeline_p.add_argument("-f", "--file", required=True)
    timeline_p.add_argument("-o", "--output", default="")
    timeline_p.add_argument("--format", choices=["json", "csv"], default="json")

    tree_p = sub.add_parser("process-tree", help="Build process tree")
    tree_p.add_argument("-f", "--file", required=True)
    tree_p.add_argument("--json", action="store_true", help="Output as JSON")

    diff_p = sub.add_parser("diff", help="Compare two memory dumps")
    diff_p.add_argument("--before", required=True, help="Path to first dump")
    diff_p.add_argument("--after", required=True, help="Path to second dump")
    diff_p.add_argument("-o", "--output", default="")

    strings_p = sub.add_parser("strings", help="Extract strings from memory dump")
    strings_p.add_argument("-f", "--file", required=True)
    strings_p.add_argument("--suspicious-only", action="store_true")
    strings_p.add_argument("--min-length", type=int, default=4)
    strings_p.add_argument("-o", "--output", default="")

    report_p = sub.add_parser("report", help="Generate analysis report")
    report_p.add_argument("-f", "--file", required=True)
    report_p.add_argument("--case-id", default="")
    report_p.add_argument("--analyst", default="")
    report_p.add_argument("--format", choices=["html", "json", "csv"], default="html")
    report_p.add_argument("-o", "--output-dir", default="reports")

    validate_p = sub.add_parser("validate", help="Validate a memory dump file")
    validate_p.add_argument("-f", "--file", required=True)

    capture_p = sub.add_parser("capture", help="Capture live memory")
    capture_p.add_argument("-o", "--output", default="captures")
    capture_p.add_argument("--method", default="", help="Capture method")

    case_p = sub.add_parser("case", help="Case management")
    case_sub = case_p.add_subparsers(dest="case_command")
    case_create = case_sub.add_parser("create")
    case_create.add_argument("--title", required=True)
    case_create.add_argument("--analyst", default="")
    case_create.add_argument("--priority", default="medium")
    case_list = case_sub.add_parser("list")
    case_list.add_argument("--status", default="")

    api_p = sub.add_parser("api", help="Start REST API server")
    api_p.add_argument("--host", default="127.0.0.1")
    api_p.add_argument("--port", type=int, default=8443)
    api_p.add_argument("--ssl-cert", default="")
    api_p.add_argument("--ssl-key", default="")

    plugin_p = sub.add_parser("plugin", help="Run a specific plugin")
    plugin_p.add_argument("-f", "--file", required=True)
    plugin_p.add_argument("-c", "--cmd", required=True, help="Plugin command name")

    parser.add_argument("--config", default="", help="Config file path")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--version", action="version", version="MFA 1.0.0")

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    from .core.config import Config
    config = Config.from_file(args.config) if args.config else Config.from_env()

    if args.command == "analyze":
        _cmd_analyze(args, config)
    elif args.command == "scan":
        _cmd_scan(args, config)
    elif args.command == "timeline":
        _cmd_timeline(args, config)
    elif args.command == "process-tree":
        _cmd_process_tree(args, config)
    elif args.command == "diff":
        _cmd_diff(args, config)
    elif args.command == "strings":
        _cmd_strings(args, config)
    elif args.command == "report":
        _cmd_report(args, config)
    elif args.command == "validate":
        _cmd_validate(args, config)
    elif args.command == "capture":
        _cmd_capture(args, config)
    elif args.command == "case":
        _cmd_case(args, config)
    elif args.command == "api":
        _cmd_api(args, config)
    elif args.command == "plugin":
        _cmd_plugin(args, config)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_analyze(args, config):
    from .core.engine import ForensicsEngine
    engine = ForensicsEngine(config)
    validation = engine.load_dump(args.file)
    print(f"Loaded: {args.file} ({validation.format_detected}, {validation.file_size / 1048576:.1f} MB)")
    print(f"Profile: {engine.profile.os_type} {engine.profile.os_version} ({engine.profile.architecture})")

    if args.plugins:
        results = engine.run_plugins(args.plugins, max_workers=args.max_workers)
    else:
        results = engine.full_analysis()

    for plugin, result in results.items():
        status = f"{result.count} rows" if not result.error else f"ERROR: {result.error}"
        print(f"  {plugin}: {status} ({result.duration:.1f}s)")

    if args.output:
        engine.export_results(args.output)
        print(f"Results exported to {args.output}")


def _cmd_scan(args, config):
    from .core.engine import ForensicsEngine
    engine = ForensicsEngine(config)
    engine.load_dump(args.file)
    engine.full_analysis()

    results = {}
    run_all = args.all

    if run_all or args.yara:
        from .detection.yara_scanner import YaraScanner
        scanner = YaraScanner(rules_dir=args.yara_rules)
        scanner.load_rules()
        yara_result = scanner.scan_file(args.file)
        results["yara"] = yara_result
        print(f"YARA: {len(yara_result.matches)} matches ({yara_result.rules_loaded} rules)")

    if run_all or args.rootkit:
        from .detection.rootkit import RootkitDetector
        detector = RootkitDetector(engine)
        report = detector.full_scan()
        results["rootkit"] = report
        print(f"Rootkit: {report.findings_count} findings (risk={report.overall_risk:.2f})")

    if run_all or args.injection:
        from .detection.injection import InjectionDetector
        detector = InjectionDetector(engine)
        report = detector.scan()
        results["injection"] = report
        print(f"Injection: {report.suspicious_count} findings ({report.critical_count} critical)")

    if run_all or args.anomaly:
        from .detection.anomaly import AnomalyDetector
        detector = AnomalyDetector(config.detection)
        pslist = engine.get_result("windows.pslist.PsList")
        netscan = engine.get_result("windows.netscan.NetScan")
        processes = pslist.rows if pslist else []
        connections = netscan.rows if netscan else []
        report = detector.analyze(processes, connections)
        results["anomaly"] = report
        print(f"Anomaly: {report.total_findings} findings (risk={report.overall_risk:.2f})")

    if run_all or args.ioc:
        from .detection.ioc_extractor import IOCExtractor
        extractor = IOCExtractor()
        report = extractor.extract_from_results(engine.all_results())
        results["iocs"] = report
        print(f"IOCs: {report.total_count} extracted")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({k: v.__dict__ if hasattr(v, "__dict__") else v for k, v in results.items()},
                      f, indent=2, default=str)


def _cmd_timeline(args, config):
    from .core.engine import ForensicsEngine
    from .analysis.timeline import TimelineAnalyzer
    engine = ForensicsEngine(config)
    engine.load_dump(args.file)
    engine.full_analysis()
    analyzer = TimelineAnalyzer()
    events = analyzer.build_timeline(engine.all_results())
    print(f"Timeline: {len(events)} events")
    if args.output:
        if args.format == "csv":
            Path(args.output).write_text(analyzer.to_csv())
        else:
            with open(args.output, "w") as f:
                json.dump([e.__dict__ for e in events], f, indent=2, default=str)


def _cmd_process_tree(args, config):
    from .core.engine import ForensicsEngine
    from .analysis.process_tree import ProcessTreeBuilder
    engine = ForensicsEngine(config)
    engine.load_dump(args.file)
    result = engine.run_plugin("windows.pslist.PsList")
    builder = ProcessTreeBuilder()
    roots = builder.build(result.rows)
    if args.json:
        print(json.dumps(builder.render_json(roots), indent=2))
    else:
        print(builder.render_text(roots))
    stats = builder.get_statistics()
    print(f"\n{stats['total_processes']} processes, {stats['suspicious_processes']} suspicious")


def _cmd_diff(args, config):
    from .analysis.differential import DifferentialAnalyzer
    analyzer = DifferentialAnalyzer(config)
    report = analyzer.compare_dumps(args.before, args.after)
    print(f"Differential: {report.summary['total_changes']} changes")
    for key, val in report.summary.items():
        print(f"  {key}: {val}")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.summary, f, indent=2)


def _cmd_strings(args, config):
    from .analysis.strings import StringExtractor
    extractor = StringExtractor(min_length=args.min_length)
    strings = extractor.extract_from_file(args.file)
    if args.suspicious_only:
        strings = extractor.get_suspicious(strings)
    print(f"Extracted {len(strings)} strings")
    if args.output:
        Path(args.output).write_text(extractor.to_csv(strings))


def _cmd_report(args, config):
    from .core.engine import ForensicsEngine
    from .reporting.reporter import ReportGenerator
    engine = ForensicsEngine(config)
    validation = engine.load_dump(args.file)
    results = engine.full_analysis()
    case_id = args.case_id or f"MFA-{int(time.time())}"
    gen = ReportGenerator(args.output_dir, args.analyst)
    dump_info = {"dump_path": args.file, "sha256": validation.sha256,
                 "os_profile": f"{engine.profile.os_type} {engine.profile.os_version}"}
    if args.format == "html":
        path = gen.generate_html(case_id, {k: v for k, v in results.items()}, dump_info)
    elif args.format == "json":
        path = gen.generate_json(case_id, {k: v for k, v in results.items()}, dump_info)
    else:
        path = gen.generate_csv(case_id, {k: v for k, v in results.items()})
    print(f"Report generated: {path}")


def _cmd_validate(args, config):
    from .core.validator import DumpValidator
    validator = DumpValidator()
    result = validator.validate(args.file)
    print(f"File: {result.file_path}")
    print(f"Size: {result.file_size / 1048576:.1f} MB")
    print(f"Format: {result.format_detected}")
    print(f"SHA-256: {result.sha256}")
    print(f"MD5: {result.md5}")
    print(f"Valid: {result.valid}")
    for e in result.errors:
        print(f"  ERROR: {e}")
    for w in result.warnings:
        print(f"  WARNING: {w}")


def _cmd_capture(args, config):
    from .acquisition.capture import MemoryCapture
    capturer = MemoryCapture(args.output)
    tools = capturer.list_available_tools()
    print(f"Available tools: {', '.join(tools) if tools else 'none'}")
    result = capturer.capture(method=args.method)
    if result.success:
        print(f"Captured: {result.dump_path} ({result.file_size / 1048576:.1f} MB in {result.duration:.1f}s)")
    else:
        print(f"Capture failed: {result.error}")


def _cmd_case(args, config):
    from .case.manager import CaseManager
    mgr = CaseManager(config.case.case_dir)
    if args.case_command == "create":
        case = mgr.create_case(args.title, analyst=args.analyst, priority=args.priority)
        print(f"Created case {case.id}: {case.title}")
    elif args.case_command == "list":
        cases = mgr.list_cases(status=args.status or None)
        for c in cases:
            print(f"  {c.id} [{c.status}] {c.title} ({c.analyst})")
    else:
        print("Usage: mfa case {create|list}")


def _cmd_api(args, config):
    from .api.server import create_app
    config.api.host = args.host
    config.api.port = args.port
    app = create_app(config)
    import uvicorn
    ssl_kwargs = {}
    if args.ssl_cert:
        ssl_kwargs["ssl_certfile"] = args.ssl_cert
        ssl_kwargs["ssl_keyfile"] = args.ssl_key
    uvicorn.run(app, host=args.host, port=args.port, **ssl_kwargs)


def _cmd_plugin(args, config):
    import pkgutil
    import importlib.util
    from . import plugins
    plugin_commands = {}
    for importer, modname, ispkg in pkgutil.iter_modules(plugins.__path__):
        plugin_path = os.path.join(plugins.__path__[0], modname + ".py")
        spec = importlib.util.spec_from_file_location(modname, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "register"):
            plugin_commands.update(module.register())

    if args.cmd in plugin_commands:
        plugin_commands[args.cmd](args)
    else:
        print(f"Unknown plugin: {args.cmd}")
        print(f"Available: {', '.join(sorted(plugin_commands.keys()))}")


import time

if __name__ == "__main__":
    main()
