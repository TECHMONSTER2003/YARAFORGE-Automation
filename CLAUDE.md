# CLAUDE.md

Context for Claude Code (and humans) working in this repo.

## What this is
**yaraforge** — mini project for 21CSC572J Applied Malware Analysis (Topic 28: YARA Rule Creation for Malware
Family Detection). Given a folder of samples from one family and a folder of goodware, it statically extracts
features, synthesises a YARA rule, and evaluates it (confusion matrix, precision/recall/FPR, leave-one-out).
**No sample is ever executed** — keep it that way in any change.

The "malware" is **MockBot**, a harmless simulated family cross-compiled from
`corpus_builder/mockbot_template.c` (8 builds varying arch/opt/XOR key/junk; `mockbot_v3_drift` changes mutex + UA
to test drift). The clean set is benign mingw builds (incl. a near-miss updater using the same APIs) plus any
`--extra-clean` PE directories.

## Layout
| Path | Role |
|---|---|
| `yaraforge/cli.py` | `build` / `scan` / `triage` subcommands (`python -m yaraforge ...`) |
| `yaraforge/pipeline.py` | orchestration: parallel per-sample analysis (cached in `<out>/cache`), goodware index, LOO |
| `yaraforge/triage.py` | pefile profile: hashes, entropy, sections, imports, imphash, packer hints |
| `yaraforge/strings_ext.py` | ASCII/UTF-16 strings + FLOSS subprocess (optional) |
| `yaraforge/capa_runner.py` | capa subprocess → capabilities with ATT&CK/MBC |
| `yaraforge/scoring.py` | candidate scoring, goodware rejection, prefix generalisation |
| `yaraforge/yaragen.py` | writes + compile-checks the `.yar` (strings rule + imports-only baseline) |
| `yaraforge/evaluate.py` | scanning + metrics |
| `yaraforge/reporting.py` | `report.json`, `iocs.csv`, `attack.csv`, `summary.md` |
| `yaraforge/config.py` | **every threshold lives here** (coverage, condition ratio, filesize margin, stoplist) |
| `corpus_builder/` | MockBot template, clean program sources, `build_corpus.py` |
| `rules/capa_custom/` | 10 lab capa rules (ATT&CK-mapped); `rules/capa_sigs/` FLIRT sigs |
| `tools/mingw_shim/` | Windows-only: `i686-/x86_64-w64-mingw32-gcc.cmd` → `zigcc.py` → `zig cc` |
| `run_demo.sh` / `setup_wsl.sh` | Linux/WSL demo + setup |
| `run_demo_windows.ps1` | Windows-native demo (no WSL) |
| `out/` | reference results from the original Linux (gcc) run — used in the report, don't overwrite |
| `out_demo/` | results from the Windows run |
| `docs/logs/` | verbatim logs quoted in the report appendix |

## Running
Windows (verified 2026-10-25, Python 3.13, Windows 11):
```powershell
powershell -ExecutionPolicy Bypass -File .\run_demo_windows.ps1
```
Creates `.venv` if missing (yara-python, pefile, flare-capa, pytest, ziglang), builds `corpus/`, runs tests,
builds the rule into `out_demo/`, scans. Manual steps need `tools\mingw_shim` and `.venv\Scripts` on PATH first.

Linux/WSL: `./setup_wsl.sh && source .venv/bin/activate && ./run_demo.sh` (writes `out/` and `docs/logs/`).

Tests: `python -m pytest -q tests` (15 tests, run in <1 s, need no corpus).

`build` exits **3** if the strings rule false-positives on goodware (CI gate), 0 otherwise.

## Windows-specific gotchas
- The global Windows Python may have the unrelated PyPI package `yara` (fails loading `libyara.dll`). Always use
  `.venv` with `yara-python`.
- `flare-floss` does not pip-install on Python 3.13/Windows (`binary2strings` has no wheel). FLOSS is optional:
  the pipeline logs `floss not found on PATH` and continues, but the XOR-decoded C2 URL is then not recovered.
  Drop the standalone `floss.exe` (mandiant/flare-floss v3.2.0 release) into `tools/floss/` to enable it.
- No mingw on Windows → `tools/mingw_shim` maps the compiler names to `zig cc`. The shim drops
  `-Wl,--no-insert-timestamp` (unsupported by lld) and adds `-fno-sanitize=undefined` (zig enables UBSan at
  `-O0`, which bloated -O0 builds to ~500 KB). Zig builds differ from gcc builds, so hashes/selected strings differ
  from `out/`.
- The Windows demo uses `.venv\Lib\site-packages` and `C:\Program Files\Git\mingw64\bin` as extra goodware
  (153 clean files total vs 99 in the Linux run).

## Reference results
| Run | Goodware | Strings rule | Imports baseline | LOO |
|---|---|---|---|---|
| `out/` (Linux, gcc) | 99 | TP 8, FP 0, P=R=1.0 | 2 FP (FPR 0.020) | 8/8 |
| `out_demo/` (Windows, zig, no FLOSS) | 153 | TP 8, FP 0, P=R=1.0 | 0 FP | 8/8 |

The "imports-only rules are weak" point in the report relies on the `out/` numbers.

## Not committed (see .gitignore)
`.venv/`, `corpus/` (~270 MB, contains copied third-party DLLs; reproducible from `--seed`), `*/cache/`,
`tools/floss/`, `__pycache__`, `.pytest_cache`.

## Known nits
- `yaraforge/scoring.py` docstring has an invalid escape `\-` → `SyntaxWarning` under pytest (harmless).
