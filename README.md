# yaraforge — Automated YARA Rule Creation for Malware Family Detection

Mini project for **21CSC572J Applied Malware Analysis** (Topic 28: *YARA Rule Creation for Malware Family Detection*).

yaraforge takes a folder of samples from one malware family and a folder of clean (goodware) files, extracts
static features with open-source tools, and generates a YARA rule. It then measures the rule (precision, recall,
false-positive rate, leave-one-out cross-validation) before anyone deploys it.

**No sample is ever executed.** All analysis is static.

## Pipeline

```
samples/ ──► triage (pefile) ──► strings + FLOSS ──► capa (ATT&CK) ──┐
                                                                   ├─► scoring ──► YARA synthesis ──► evaluation ──► reports
goodware/ ─► strings + imports (baseline index) ────────────────────┘                                 (TP/FP, LOO)
```

| Stage | Module | Tool | Output |
|---|---|---|---|
| 1 Triage | `triage.py` | pefile | hashes, type, entropy, sections, imports, imphash, packer hints |
| 2 Strings | `strings_ext.py` | built-in + FLOSS 3.x | ASCII/UTF-16 strings, decoded, stack and tight strings |
| 3 Capabilities | `capa_runner.py` | capa | capabilities mapped to ATT&CK and MBC |
| 4 Scoring | `scoring.py` | — | ranked family-specific strings with the reason each rejected string was dropped |
| 5 Synthesis | `yaragen.py` | yara-python | `.yar` file (strings rule + API-only baseline rule), compile-checked |
| 6 Evaluation | `evaluate.py` | yara-python | confusion matrix, leave-one-out cross-validation |
| 7 Reporting | `reporting.py` | — | `report.json`, `iocs.csv`, `attack.csv`, `summary.md`, logs |

## Quick start (WSL2 Ubuntu / Linux)

```bash
./setup_wsl.sh && source .venv/bin/activate
./run_demo.sh                      # builds harmless corpus, runs tests, builds + evaluates rule, scans
```

Manual:

```bash
python3 -m yaraforge build --family MockBot \
    --malware corpus/family/mockbot --clean corpus/clean --out out \
    --capa-rules rules/capa_custom --capa-sigs rules/capa_sigs
python3 -m yaraforge scan   --rules out/mockbot.yar --target corpus
python3 -m yaraforge triage corpus/family/mockbot/mockbot_v2_a.exe
```

The exit code is non-zero if the generated strings rule false-positives on goodware, so the build can act as a CI gate.

## Test corpus (harmless)

`corpus_builder/` cross-compiles **MockBot**, a *simulated* family of 8 benign Windows PE files. They share family
traits: a mutex, a user agent, a config marker with a random per-build suffix, an XOR-encoded URL on the reserved
`.invalid` domain, and a stack-built tag. Builds vary in architecture, optimisation level, XOR key and junk data,
and one build is a deliberately drifted "v3". The clean set contains benign builds, including a **near-miss updater**
that uses the same APIs, plus about 90 real third-party Windows DLL/EXE files. Builds are byte-reproducible (`--seed`).

## Using real samples (optional)

Static analysis only. Keep samples in password-protected zips (`infected`), store them on the WSL ext4 filesystem
(not `/mnt/c`), never execute them, and do not use a corporate or managed laptop.

```bash
python3 -m yaraforge build --family AgentTesla --malware ~/samples/agenttesla \
    --clean ~/goodware --out out_at --capa-rules rules/capa_official
```

## Layout

```
yaraforge/        core package (cli, pipeline, triage, strings_ext, capa_runner, scoring, yaragen, evaluate, reporting)
corpus_builder/   harmless family template + clean programs + builder
rules/            capa_custom (10 lab rules, ATT&CK-mapped), capa_sigs (FLIRT)
tests/            pytest unit tests
docs/logs/        verbatim logs used in the report appendix
out/              generated rule, report.json, iocs.csv, attack.csv, summary.md
```
