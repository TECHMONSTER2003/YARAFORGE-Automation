"""Stage 6 - evaluation.

* Confusion matrix per rule over the family set (positives) and clean set (negatives).
* Leave-one-out (LOO) cross-validation: rebuild the rule from N-1 samples, test the
  held-out one. This estimates how the rule handles a *new, unseen* variant - the
  number that actually matters operationally, since a rule that only matches its
  own training samples is a hash list with extra steps.
"""
from __future__ import annotations

from pathlib import Path

import yara

from yaraforge import logutil

log = logutil.get("eval")


def scan(rules: yara.Rules, paths: list[Path], timeout: int = 60) -> dict[str, dict]:
    """Return {file_name: {rule_name: [matched string identifiers]}}."""
    out: dict[str, dict] = {}
    for p in paths:
        try:
            matches = rules.match(str(p), timeout=timeout)
        except yara.Error as exc:
            log.warning("scan error on %s: %s", p.name, exc)
            out[p.name] = {"_error": str(exc)}
            continue
        out[p.name] = {
            m.rule: sorted({s.identifier for s in m.strings}) for m in matches
        }
    return out


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4)}


def confusion(rule_name: str, pos: dict[str, dict], neg: dict[str, dict]) -> dict:
    tp = sum(1 for r in pos.values() if rule_name in r)
    fn = len(pos) - tp
    fp_files = sorted(f for f, r in neg.items() if rule_name in r)
    fp = len(fp_files)
    tn = len(neg) - fp
    m = metrics(tp, fp, tn, fn)
    m["missed"] = sorted(f for f, r in pos.items() if rule_name not in r)
    m["false_positives"] = fp_files
    return m
