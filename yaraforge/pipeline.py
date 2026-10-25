"""Orchestration: per-sample analysis (parallel + cached), goodware baseline,
candidate selection, rule synthesis, evaluation, LOO cross-validation."""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import yara

from yaraforge import capa_runner, evaluate, logutil, scoring, strings_ext, triage, yaragen
from yaraforge.config import Config

log = logutil.get("pipeline")


# ------------------------------------------------------------------------------- helpers
def list_files(d: Path) -> list[Path]:
    if not d.is_dir():
        raise SystemExit(f"not a directory: {d}")
    return sorted(p for p in d.rglob("*") if p.is_file() and not p.name.startswith("."))


def _cache_key(sha256: str, cfg: Config) -> str:
    salt = json.dumps([cfg.use_floss, cfg.use_capa, cfg.capa_rules, cfg.min_string_len, cfg.max_string_len])
    return f"{sha256}_{hashlib.md5(salt.encode()).hexdigest()[:8]}"


def analyse_sample(path: Path, cfg: Config, cache_dir: Path | None) -> dict:
    """Full static analysis of one family sample. Runs in a worker process."""
    t0 = time.time()
    prof, data = triage.triage(path, cfg.max_file_size)
    if data is None:
        return {"profile": prof, "skipped": prof["skipped"]}

    cache_file = cache_dir / f"{_cache_key(prof['sha256'], cfg)}.json" if cache_dir else None
    if cache_file and cache_file.exists():
        feat = json.loads(cache_file.read_text())
        feat["profile"]["file"], feat["profile"]["path"] = prof["file"], prof["path"]
        feat["cached"] = True
        return feat

    st = strings_ext.static_strings(data, cfg.min_string_len, cfg.max_string_len)
    feat = {
        "profile": prof,
        "strings": {k: sorted(v) for k, v in st.items()},
        "floss": strings_ext.floss_strings(path, cfg.floss_timeout) if cfg.use_floss else {"error": "disabled"},
        "capa": (capa_runner.run_capa(path, cfg.capa_rules, cfg.capa_sigs, cfg.capa_timeout)
                 if cfg.use_capa and prof.get("type") == "PE" else {"error": "disabled or non-PE"}),
        "elapsed_s": None,
        "cached": False,
    }
    feat["elapsed_s"] = round(time.time() - t0, 1)
    if cache_file:
        cache_file.write_text(json.dumps(feat))
    return feat


def _log_sample(feat: dict) -> None:
    p = feat["profile"]
    name = p["file"]
    if "skipped" in feat:
        log.warning("%s skipped: %s", name, feat["skipped"])
        return
    lt = logutil.get("triage")
    pe = p.get("pe", {})
    if "pe_error" in pe:
        lt.warning("%s | %s | malformed PE: %s", name, p["type"], pe["pe_error"])
    desc = f"{pe.get('pe_type', p['type'])} {pe.get('machine', '')}".strip()
    lt.info("%-22s | %-14s | %7.1f KB | H=%.2f | imphash=%s | sha256=%s..",
            name, desc, p["size"] / 1024, p["entropy"], (pe.get("imphash") or "-")[:12], p["sha256"][:16])
    for hint in pe.get("packer_hints", []):
        lt.warning("%-22s | packer heuristic: %s", name, hint)

    ls = logutil.get("strings")
    fl = feat.get("floss", {})
    fl_txt = (f"decoded={len(fl.get('decoded', []))} stack={len(fl.get('stack', []))} "
              f"tight={len(fl.get('tight', []))}") if "error" not in fl else f"FLOSS error: {fl['error']}"
    ls.info("%-22s | ascii=%d wide=%d | %s%s", name, len(feat["strings"]["ascii"]),
            len(feat["strings"]["wide"]), fl_txt, " (cached)" if feat.get("cached") else f" ({feat['elapsed_s']}s)")
    for s in fl.get("decoded", []):
        ls.debug("%-22s | decoded: %r", name, s)
    for s in fl.get("stack", []):
        ls.debug("%-22s | stack  : %r", name, s)

    lc = logutil.get("capa")
    cp = feat.get("capa", {})
    if "error" in cp:
        lc.warning("%-22s | %s", name, cp["error"])
    else:
        ids = sorted({a["id"] for c in cp["capabilities"] for a in c["attack"]})
        lc.info("%-22s | %d capabilities | ATT&CK %s", name, len(cp["capabilities"]), ",".join(ids) or "-")


def build_goodware_index(paths: list[Path], cfg: Config, exclude_sha: set[str]) -> scoring.GoodwareIndex:
    lg = logutil.get("goodware")
    gw = scoring.GoodwareIndex()
    skipped = Counter()
    for p in paths:
        prof, data = triage.triage(p, cfg.max_file_size)
        if data is None:
            skipped[prof["skipped"]] += 1
            continue
        if prof["sha256"] in exclude_sha:
            lg.warning("%s is also in the family set (same SHA256) - excluded from goodware", p.name)
            continue
        st = strings_ext.static_strings(data, cfg.min_string_len, cfg.max_string_len)
        imps = prof.get("pe", {}).get("imports") if prof.get("type") == "PE" else None
        if prof.get("type") == "PE" and "pe_error" in prof.get("pe", {}):
            imps = None
        gw.add(p.name, data, st, imps)
    lg.info("baseline built: %d files (%d PE), %d unique strings, %d unique imports",
            gw.file_count, gw.pe_count, len(gw.strings), len(gw.import_df))
    for reason, n in skipped.items():
        lg.warning("skipped %d goodware file(s): %s", n, reason)
    return gw


def attack_summary(family: dict[str, dict]) -> list[dict]:
    per_tech: dict[str, dict] = {}
    for name, feat in family.items():
        for cap in feat.get("capa", {}).get("capabilities", []):
            for a in cap["attack"]:
                t = per_tech.setdefault(a["id"], {"id": a["id"], "tactic": a["tactic"],
                                                  "technique": a["technique"] + (f": {a['subtechnique']}" if a["subtechnique"] else ""),
                                                  "capabilities": set(), "samples": set()})
                t["capabilities"].add(cap["name"])
                t["samples"].add(name)
    out = []
    for t in sorted(per_tech.values(), key=lambda x: (x["tactic"], x["id"])):
        out.append({**t, "capabilities": sorted(t["capabilities"]), "samples": sorted(t["samples"]),
                    "coverage": round(len(t["samples"]) / max(len(family), 1), 3)})
    return out


def extract_iocs(family: dict[str, dict], gw: scoring.GoodwareIndex) -> list[dict]:
    found: dict[tuple, set] = defaultdict(set)
    for name, feat in family.items():
        p = feat["profile"]
        found[("sha256", p["sha256"])].add(name)
        vals = [(s, "static") for s in feat["strings"]["ascii"] + feat["strings"]["wide"]]
        vals += [(s, "floss-decoded") for s in feat.get("floss", {}).get("decoded", [])]
        vals += [(s, "floss-stack") for s in feat.get("floss", {}).get("stack", [])]
        for s, origin in vals:
            cls = scoring.ioc_class(s)
            if cls and cls != "config_marker":
                found[(cls, s, origin)].add(name)
    iocs = []
    for key, samples in found.items():
        if key[0] == "sha256":
            iocs.append({"type": "sha256", "value": key[1], "origin": "file", "samples": len(samples), "in_goodware": False})
        else:
            cls, val, origin = key
            iocs.append({"type": cls, "value": val, "origin": origin, "samples": len(samples),
                         "in_goodware": gw.strings.get(val, 0) > 0})
    iocs.sort(key=lambda d: (d["type"] != "sha256", d["type"], -d["samples"], d["value"]))
    return iocs


# ------------------------------------------------------------------------------- main flow
def run(family_name: str, malware_dir: Path, clean_dir: Path, out_dir: Path, cfg: Config,
        loo: bool = True) -> dict:
    t_start = time.time()
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = out_dir / "cache"
    cache_dir.mkdir(exist_ok=True)

    mal_paths, clean_paths = list_files(malware_dir), list_files(clean_dir)
    log.info("family=%s | samples=%d | goodware=%d | workers=%d | floss=%s | capa=%s",
             family_name, len(mal_paths), len(clean_paths), cfg.workers, cfg.use_floss, cfg.use_capa)
    log.info("SAFETY: static analysis only - no sample is executed")
    if len(mal_paths) < 2:
        raise SystemExit("need at least 2 family samples to find shared traits")

    # ---- stage 1-3: per-sample analysis (parallel) ----------------------------------
    family: dict[str, dict] = {}
    seen_sha: dict[str, str] = {}
    with ProcessPoolExecutor(max_workers=cfg.workers) as ex:
        futs = {ex.submit(analyse_sample, p, cfg, cache_dir): p for p in mal_paths}
        results = []
        for fut in as_completed(futs):
            p = futs[fut]
            try:
                results.append(fut.result())
            except Exception as exc:  # worker crash must not kill the run
                log.error("%s analysis failed: %s: %s", p.name, type(exc).__name__, exc)
    for feat in sorted(results, key=lambda f: f["profile"]["file"]):
        _log_sample(feat)
        if "skipped" in feat:
            continue
        sha = feat["profile"]["sha256"]
        if sha in seen_sha:
            log.warning("%s is a duplicate of %s (same SHA256) - ignored", feat["profile"]["file"], seen_sha[sha])
            continue
        seen_sha[sha] = feat["profile"]["file"]
        family[feat["profile"]["file"]] = feat
    if len(family) < 2:
        raise SystemExit("fewer than 2 usable family samples after triage")

    # ---- goodware baseline -----------------------------------------------------------
    gw = build_goodware_index(clean_paths, cfg, set(seen_sha))

    # ---- stage 4: candidate selection ------------------------------------------------
    lsc = logutil.get("scoring")
    selected, stats = scoring.select_candidates(family, gw, cfg)
    lsc.info("unique strings=%d | survivors=%d | prefix-generalised=%d | verified=%d | selected=%d",
             stats["unique_strings"], stats["survivors_before_verify"], stats["prefix_generalised"],
             stats["verified"], stats["selected"])
    lsc.info("rejections: %s", ", ".join(f"{k}={v}" for k, v in sorted(stats["rejected"].items(), key=lambda x: -x[1])))
    for c in selected:
        lsc.info("  score=%.3f cov=%.2f src=%-7s ioc=%-13s %r", c.score, c.coverage, c.source, c.ioc or "-", c.value)
    imports = scoring.select_imports(family, gw)
    for imp in imports:
        lsc.info("  baseline import %-40s goodware_ratio=%.3f", imp["import"], imp["goodware_ratio"])

    # ---- stage 5: rule synthesis -----------------------------------------------------
    attack = attack_summary(family)
    attack_ids = [t["id"] for t in attack if t["coverage"] >= cfg.min_coverage]
    lg = logutil.get("yaragen")
    try:
        built = yaragen.build_rules(family_name, selected, imports, [f["profile"] for f in family.values()],
                                    attack_ids, cfg)
    except (ValueError, yara.SyntaxError) as exc:
        lg.error("rule generation failed: %s", exc)
        raise SystemExit(2)
    rule_path = out_dir / f"{family_name.lower()}.yar"
    rule_path.write_text(built["text"])
    lg.info("compiled OK -> %s | strings=%d | condition='%d of them' | filesize<%dKB",
            rule_path.name, built["string_count"], built["condition_n"], built["size_limit_kb"])

    # ---- stage 6: evaluation ---------------------------------------------------------
    le = logutil.get("eval")
    rules = yara.compile(source=built["text"])
    fam_paths = [Path(f["profile"]["path"]) for f in family.values()]
    pos, neg = evaluate.scan(rules, fam_paths), evaluate.scan(rules, clean_paths)
    eval_res = {}
    for rname in filter(None, [built["strings_rule"], built["imports_rule"]]):
        m = evaluate.confusion(rname, pos, neg)
        eval_res[rname] = m
        le.info("%-28s TP=%d FN=%d FP=%d TN=%d | precision=%.3f recall=%.3f F1=%.3f FPR=%.4f",
                rname, m["tp"], m["fn"], m["fp"], m["tn"], m["precision"], m["recall"], m["f1"], m["fpr"])
        for f in m["missed"]:
            le.warning("%-28s missed family sample: %s", rname, f)
        for f in m["false_positives"]:
            le.warning("%-28s FALSE POSITIVE on goodware: %s", rname, f)
    per_sample_hits = {f: sorted(r.get(built["strings_rule"], [])) for f, r in pos.items()}
    for f, ids in per_sample_hits.items():
        le.debug("%-22s matched %d/%d strings: %s", f, len(ids), built["string_count"], " ".join(ids))

    # ---- LOO cross-validation --------------------------------------------------------
    loo_res = []
    if loo and len(family) >= 3:
        lv = logutil.get("loo")
        for held in sorted(family):
            train = {k: v for k, v in family.items() if k != held}
            sel, _ = scoring.select_candidates(train, gw, cfg, quiet=True)
            try:
                b = yaragen.build_rules(family_name, sel, [], [f["profile"] for f in train.values()], [], cfg)
            except (ValueError, yara.SyntaxError) as exc:
                lv.warning("fold held-out=%s: rule build failed (%s)", held, exc)
                loo_res.append({"held_out": held, "detected": False, "error": str(exc)})
                continue
            r = yara.compile(source=b["text"])
            hit = evaluate.scan(r, [Path(family[held]["profile"]["path"])])[held]
            gw_fp = sum(1 for v in evaluate.scan(r, clean_paths).values() if b["strings_rule"] in v)
            detected = b["strings_rule"] in hit
            loo_res.append({"held_out": held, "detected": detected,
                            "matched": hit.get(b["strings_rule"], []), "rule_strings": b["string_count"],
                            "goodware_fp": gw_fp})
            (lv.info if detected else lv.warning)(
                "held-out=%-22s %-8s matched=%d/%d need=%d goodware_FP=%d", held,
                "DETECTED" if detected else "MISSED", len(hit.get(b["strings_rule"], [])),
                b["string_count"], b["condition_n"], gw_fp)
        rate = sum(r["detected"] for r in loo_res) / len(loo_res)
        lv.info("LOO detection rate = %d/%d (%.1f%%)", sum(r["detected"] for r in loo_res), len(loo_res), rate * 100)

    iocs = extract_iocs(family, gw)
    elapsed = round(time.time() - t_start, 1)
    log.info("done in %.1fs", elapsed)

    return {
        "family": family_name, "config": cfg.as_dict(), "elapsed_s": elapsed,
        "samples": [{"file": f["profile"]["file"], "sha256": f["profile"]["sha256"], "size": f["profile"]["size"],
                     "type": f["profile"].get("pe", {}).get("pe_type", f["profile"]["type"]),
                     "machine": f["profile"].get("pe", {}).get("machine"),
                     "imphash": f["profile"].get("pe", {}).get("imphash"),
                     "entropy": f["profile"]["entropy"],
                     "sections": f["profile"].get("pe", {}).get("sections", []),
                     "import_count": f["profile"].get("pe", {}).get("import_count"),
                     "packer_hints": f["profile"].get("pe", {}).get("packer_hints", []),
                     "floss": {k: f.get("floss", {}).get(k, []) for k in ("decoded", "stack", "tight")},
                     "capabilities": [c["name"] for c in f.get("capa", {}).get("capabilities", [])]}
                    for f in family.values()],
        "goodware": {"files": gw.file_count, "pe": gw.pe_count, "unique_strings": len(gw.strings)},
        "scoring": {"stats": stats, "selected": [c.to_dict() for c in selected], "imports": imports},
        "attack": attack,
        "rule": {"path": str(rule_path), **{k: v for k, v in built.items() if k != "text"}},
        "evaluation": eval_res, "per_sample_hits": per_sample_hits,
        "loo": loo_res, "iocs": iocs,
    }
