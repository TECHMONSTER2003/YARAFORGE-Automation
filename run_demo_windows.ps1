# Windows-native equivalent of run_demo.sh (no WSL needed).
# Uses .venv (yara-python, pefile, capa, pytest, ziglang) and tools\mingw_shim, which
# forwards the mingw cross-compiler names to `zig cc`. FLOSS is used if floss.exe is on PATH.
#
#   powershell -ExecutionPolicy Bypass -File .\run_demo_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    python -m venv .venv
    & $py -m pip install -q "yara-python>=4.5" "pefile>=2023.2.7" "flare-capa>=9.0" "pytest>=8.0" ziglang
}
$env:PATH = "$PSScriptRoot\tools\mingw_shim;$PSScriptRoot\tools\floss;$PSScriptRoot\.venv\Scripts;$env:PATH"
$out = "out_demo"

Write-Host "== 1. build harmless corpus" -ForegroundColor Cyan
if (Test-Path corpus) { Remove-Item -Recurse -Force corpus }
& $py corpus_builder\build_corpus.py --out corpus --extra-clean .venv\Lib\site-packages --extra-clean "C:\Program Files\Git\mingw64\bin"

Write-Host "== 2. unit tests" -ForegroundColor Cyan
& $py -m pytest -q tests

Write-Host "== 3. generate + evaluate rule" -ForegroundColor Cyan
& $py -m yaraforge build --family MockBot --malware corpus/family/mockbot --clean corpus/clean --out $out `
    --capa-rules rules/capa_custom --capa-sigs rules/capa_sigs
Write-Host "build exit code: $LASTEXITCODE (0 = no false positives on goodware)"

Write-Host "== 4. scan with generated rule" -ForegroundColor Cyan
& $py -m yaraforge scan --rules "$out/mockbot.yar" --target corpus

Write-Host "== done: see $out\mockbot.yar and $out\summary.md" -ForegroundColor Green
