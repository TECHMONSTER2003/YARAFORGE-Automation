"""Command-line interface.

  yaraforge build  --family MockBot --malware DIR --clean DIR --out DIR [options]
  yaraforge scan   --rules FILE.yar --target DIR [--json OUT]
  yaraforge triage FILE [FILE ...]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yara

from yaraforge import __version__, logutil, pipeline, reporting, strings_ext, triage
from yaraforge.config import Config


def _cmd_build(a: argparse.Namespace) -> int:
    out = Path(a.out)
    logutil.setup(out / "logs" / "yaraforge.log", a.verbose)
    cfg = Config(
        use_floss=not a.no_floss, use_capa=not a.no_capa,
        capa_rules=a.capa_rules, capa_sigs=a.capa_sigs,
        workers=a.workers, min_coverage=a.min_coverage,
        max_rule_strings=a.max_strings, author=a.author,
    )
    log = logutil.get("cli")
    log.info("yaraforge %s | python %s | yara-python %s", __version__, sys.version.split()[0], yara.__version__)
    res = pipeline.run(a.family, Path(a.malware), Path(a.clean), out, cfg, loo=not a.no_loo)
    for p in reporting.write_all(res, out):
        log.info("wrote %s", p)
    strings_rule = res["evaluation"].get(res["rule"]["strings_rule"], {})
    return 0 if strings_rule.get("fp", 1) == 0 else 3      # non-zero exit if the rule FPs (CI gate)


def _cmd_scan(a: argparse.Namespace) -> int:
    logutil.setup(None, a.verbose)
    log = logutil.get("scan")
    try:
        rules = yara.compile(filepath=a.rules)
    except yara.Error as exc:
        log.error("cannot compile %s: %s", a.rules, exc)
        return 2
    paths = pipeline.list_files(Path(a.target))
    from yaraforge.evaluate import scan
    res = scan(rules, paths)
    hits = 0
    for f, r in res.items():
        if r:
            hits += 1
            for rule, ids in r.items():
                log.info("MATCH %-28s %-30s strings=%s", rule, f, ",".join(ids))
    log.info("scanned %d files, %d matched", len(paths), hits)
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=2))
    return 0


def _cmd_triage(a: argparse.Namespace) -> int:
    logutil.setup(None, a.verbose)
    cfg = Config()
    for f in a.files:
        prof, data = triage.triage(Path(f), cfg.max_file_size)
        if data is not None:
            st = strings_ext.static_strings(data, cfg.min_string_len, cfg.max_string_len)
            prof["string_counts"] = {k: len(v) for k, v in st.items()}
        print(json.dumps(prof, indent=2, default=list))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="yaraforge", description="Automated YARA rule generation for malware families")
    ap.add_argument("--version", action="version", version=f"yaraforge {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="analyse a family and generate + evaluate YARA rules")
    b.add_argument("--family", required=True, help="family name, e.g. AgentTesla")
    b.add_argument("--malware", required=True, help="directory of family samples")
    b.add_argument("--clean", required=True, help="directory of goodware (negative set)")
    b.add_argument("--out", required=True, help="output directory")
    b.add_argument("--capa-rules", help="capa rules directory (default: capa's bundled rules)")
    b.add_argument("--capa-sigs", help="capa FLIRT signatures directory")
    b.add_argument("--workers", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    b.add_argument("--min-coverage", type=float, default=0.5)
    b.add_argument("--max-strings", type=int, default=12)
    b.add_argument("--author", default="yaraforge")
    b.add_argument("--no-floss", action="store_true")
    b.add_argument("--no-capa", action="store_true")
    b.add_argument("--no-loo", action="store_true", help="skip leave-one-out cross-validation")
    b.add_argument("-v", "--verbose", action="store_true")
    b.set_defaults(func=_cmd_build)

    s = sub.add_parser("scan", help="scan a directory with a rule file")
    s.add_argument("--rules", required=True)
    s.add_argument("--target", required=True)
    s.add_argument("--json")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=_cmd_scan)

    t = sub.add_parser("triage", help="print the static profile of file(s)")
    t.add_argument("files", nargs="+")
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=_cmd_triage)

    a = ap.parse_args(argv)
    return a.func(a)
