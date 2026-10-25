"""Stage 7 - outputs: report.json, iocs.csv, attack.csv, summary.md."""
from __future__ import annotations

import csv
import json
from pathlib import Path


def write_all(res: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    p = out_dir / "report.json"
    p.write_text(json.dumps(res, indent=2, default=list))
    written.append(p)

    p = out_dir / "iocs.csv"
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["type", "value", "origin", "samples", "in_goodware"])
        w.writeheader()
        w.writerows(res["iocs"])
    written.append(p)

    p = out_dir / "attack.csv"
    with p.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["technique_id", "tactic", "technique", "sample_coverage", "capabilities"])
        for t in res["attack"]:
            w.writerow([t["id"], t["tactic"], t["technique"], t["coverage"], "; ".join(t["capabilities"])])
    written.append(p)

    p = out_dir / "summary.md"
    p.write_text(_markdown(res))
    written.append(p)
    return written


def _markdown(res: dict) -> str:
    L = [f"# yaraforge report - {res['family']}", "",
         f"Samples: {len(res['samples'])} | Goodware: {res['goodware']['files']} | Runtime: {res['elapsed_s']}s", "",
         "## Rule evaluation", "", "| Rule | TP | FN | FP | TN | Precision | Recall | F1 | FPR |",
         "|---|---|---|---|---|---|---|---|---|"]
    for name, m in res["evaluation"].items():
        L.append(f"| {name} | {m['tp']} | {m['fn']} | {m['fp']} | {m['tn']} | {m['precision']:.3f} | "
                 f"{m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.4f} |")
    if res["loo"]:
        d = sum(r["detected"] for r in res["loo"])
        L += ["", f"## Leave-one-out: {d}/{len(res['loo'])} held-out samples detected", "",
              "| Held-out | Detected | Matched | Goodware FP |", "|---|---|---|---|"]
        for r in res["loo"]:
            L.append(f"| {r['held_out']} | {'yes' if r['detected'] else 'NO'} | "
                     f"{len(r.get('matched', []))}/{r.get('rule_strings', '-')} | {r.get('goodware_fp', '-')} |")
    L += ["", "## Selected strings", "", "| Score | Coverage | Source | IOC | Value |", "|---|---|---|---|---|"]
    for c in res["scoring"]["selected"]:
        L.append(f"| {c['score']:.3f} | {c['coverage']:.2f} | {c['source']} | {c['ioc'] or '-'} | `{c['value']}` |")
    L += ["", "## MITRE ATT&CK (capa)", "", "| ID | Tactic | Technique | Coverage |", "|---|---|---|---|"]
    for t in res["attack"]:
        L.append(f"| {t['id']} | {t['tactic']} | {t['technique']} | {t['coverage']:.2f} |")
    return "\n".join(L) + "\n"
