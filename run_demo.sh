#!/usr/bin/env bash
# End-to-end demo: build harmless corpus -> generate rule -> evaluate -> scan.
# Every step writes a log under docs/logs/ (these are the logs quoted in the report).
set -euo pipefail
cd "$(dirname "$0")"
LOGS=docs/logs; mkdir -p "$LOGS"

EXTRA_CLEAN=()
[ -n "${GOODWARE_DIR:-}" ] && EXTRA_CLEAN=(--extra-clean "$GOODWARE_DIR")

echo "== 1. build harmless corpus"
python3 corpus_builder/build_corpus.py --out corpus "${EXTRA_CLEAN[@]}" | tee "$LOGS/01_corpus.log"

echo "== 2. unit tests"
python3 -m pytest -q tests | tee "$LOGS/02_tests.log"

echo "== 3. generate + evaluate rule"
CAPA_RULES=${CAPA_RULES:-rules/capa_custom}
python3 -m yaraforge build --family MockBot \
    --malware corpus/family/mockbot --clean corpus/clean --out out \
    --capa-rules "$CAPA_RULES" --capa-sigs rules/capa_sigs | tee "$LOGS/03_build.log"

echo "== 4. scan with generated rule"
python3 -m yaraforge scan --rules out/mockbot.yar --target corpus | tee "$LOGS/04_scan.log"
