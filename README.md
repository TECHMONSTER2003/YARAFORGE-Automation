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

## Quick start (Windows, no WSL)

Requires Python 3.11+ and PowerShell. Everything installs into a local `.venv`.

```powershell
git clone <this-repo> yaraforge; cd yaraforge
powershell -ExecutionPolicy Bypass -File .\run_demo_windows.ps1
```

The script creates `.venv` (yara-python, pefile, flare-capa, pytest, ziglang), builds the harmless corpus, runs the
tests, builds and evaluates the rule into `out_demo/`, and scans the corpus. It takes about 2 minutes.

Windows does not ship a MinGW cross-compiler, so `tools/mingw_shim/` provides `i686-w64-mingw32-gcc` and
`x86_64-w64-mingw32-gcc` wrappers that forward to `zig cc` (from the `ziglang` pip package). FLOSS is optional:
`flare-floss` does not pip-install on Python 3.13/Windows, so download the standalone `floss.exe` from the
[FLOSS releases](https://github.com/mandiant/flare-floss/releases) into `tools/floss/` to enable decoded-string
extraction. Without it, the pipeline logs a warning and continues.

Manual steps on Windows:

```powershell
$env:PATH = "$PWD\tools\mingw_shim;$PWD\.venv\Scripts;$env:PATH"
.\.venv\Scripts\Activate.ps1
python corpus_builder\build_corpus.py --out corpus --extra-clean .venv\Lib\site-packages
python -m pytest -q tests
python -m yaraforge build --family MockBot --malware corpus/family/mockbot --clean corpus/clean --out out_demo `
    --capa-rules rules/capa_custom --capa-sigs rules/capa_sigs
python -m yaraforge scan   --rules out_demo/mockbot.yar --target corpus
python -m yaraforge triage corpus/family/mockbot/mockbot_v2_a.exe
```

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

The exit code is non-zero (3) if the generated strings rule false-positives on goodware, so the build can act as a
CI gate.

## Results

| Run | Goodware | `MockBot_Strings` | `MockBot_Imports_Baseline` | Leave-one-out |
|---|---|---|---|---|
| `out/`: Linux, mingw-gcc, FLOSS + capa | 99 | TP 8 / FP 0, precision 1.000, recall 1.000 | TP 8 / FP 2, FPR 0.020 | 8/8 |
| `out_demo/`: Windows, zig cc, capa, no FLOSS | 153 | TP 8 / FP 0, precision 1.000, recall 1.000 | TP 8 / FP 0 | 8/8 |

The strings rule detects the drifted `mockbot_v3_drift` build, which has a changed mutex and user agent, through the
shared config marker and format strings. The imports-only baseline false-positives on the near-miss updater in the
Linux run, which is why it is marked as not for deployment. Zig and gcc produce different binaries, so hashes and the
exact selected strings differ between the two runs. See `out*/summary.md` for full tables, including the ATT&CK
mapping.

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
tools/mingw_shim/ Windows: mingw compiler names -> zig cc
docs/logs/        verbatim logs used in the report appendix
out/              reference results (Linux run): rule, report.json, iocs.csv, attack.csv, summary.md
out_demo/         results from the Windows run
run_demo.sh, setup_wsl.sh   Linux/WSL setup + demo
run_demo_windows.ps1        Windows demo
```

`corpus/` and `.venv/` are not committed (see `.gitignore`). The corpus is regenerated by `build_corpus.py`; MockBot
builds are deterministic for a given `--seed`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Could not find module ... libyara.dll` | The unrelated PyPI package `yara` is installed. Use the project `.venv`, which has `yara-python`. |
| `missing cross compiler i686-w64-mingw32-gcc` | Put `tools\mingw_shim` on `PATH` (Windows) or `apt install mingw-w64` (Linux). |
| `FLOSS error: floss not found on PATH` | Optional. Install FLOSS or put `floss.exe` in `tools/floss/`. |
| `running scripts is disabled` | `Set-ExecutionPolicy -Scope Process Bypass` |
