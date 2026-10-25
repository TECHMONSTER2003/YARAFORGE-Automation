"""Unit tests for the deterministic core (no FLOSS/capa needed).  Run: pytest -q"""
import math

import pytest
import yara

from yaraforge import evaluate, scoring, strings_ext, triage, yaragen
from yaraforge.config import Config


def test_entropy_bounds():
    assert triage.shannon_entropy(b"") == 0.0
    assert triage.shannon_entropy(b"AAAA") == 0.0
    assert math.isclose(triage.shannon_entropy(bytes(range(256))), 8.0)


def test_magic_type():
    assert triage.magic_type(b"MZ\x90\x00") == "PE"
    assert triage.magic_type(b"\x7fELF....") == "ELF"
    assert triage.magic_type(b"%PDF-1.7") == "PDF"
    assert triage.magic_type(b"garbage!") == "unknown"


def test_malformed_pe_does_not_raise():
    prof = triage.pe_profile(b"MZ" + b"\x00" * 64)
    assert "pe_error" in prof


def test_static_strings_ascii_and_wide():
    data = b"\x00\x01hello_world\x00" + "WideString1".encode("utf-16le") + b"\x00\x00"
    st = strings_ext.static_strings(data, 6, 200)
    assert "hello_world" in st["ascii"]
    assert "WideString1" in st["wide"]


def test_prefixes_end_on_delimiter():
    assert scoring._prefixes("MKBCFG::v2::build=abc123", 8) == [
        "MKBCFG::", "MKBCFG::v2:", "MKBCFG::v2::", "MKBCFG::v2::build="]


@pytest.mark.parametrize("s,reason", [
    ("EFEFEFEFEFEFEFEF", "low_diversity"),
    ("476,670,838,271,043,27-", "no_letters"),
    ("v1.2.3-4.5.6-7.8.9", "mostly_digits_punct"),
    ("Global\\MkB_7f3a9c21", None),
])
def test_noise(s, reason):
    assert scoring.is_noise(s) == reason


def test_ioc_classes():
    assert scoring.ioc_class("http://x.invalid/a") == "url"
    assert scoring.ioc_class("Global\\Foo") == "mutex"
    assert scoring.ioc_class("Mozilla/4.0 (compatible)") == "user_agent"


def test_yara_escaping_compiles():
    nasty = 'C:\\path\\"quoted"\x01'
    src = f'rule t {{ strings: $a = {yaragen.yara_text_string(nasty)} condition: $a }}'
    r = yara.compile(source=src)
    assert r.match(data=nasty.encode("latin-1"))


def test_metrics():
    m = evaluate.metrics(tp=8, fp=2, tn=97, fn=0)
    assert m["precision"] == 0.8 and m["recall"] == 1.0 and m["fpr"] == round(2 / 99, 4)


def _fam(strings_per_sample):
    return {f"s{i}": {"profile": {"file": f"s{i}", "size": 1000, "type": "PE", "sha256": f"{i:064x}"},
                      "strings": {"ascii": sorted(s), "wide": []}, "floss": {}}
            for i, s in enumerate(strings_per_sample)}


def test_selection_rejects_goodware_and_generalises_prefix():
    fam = _fam([
        {"FAMILYMARK_alpha", "CFGX::build=aaaa11", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"FAMILYMARK_alpha", "CFGX::build=bbbb22", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"FAMILYMARK_alpha", "CFGX::build=cccc33", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    ])
    gw = scoring.GoodwareIndex()
    run = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    gw.add("legit.exe", run, {"ascii": {run.decode()}, "wide": set()}, {})
    sel, stats = scoring.select_candidates(fam, gw, Config())
    values = {c.value for c in sel}
    assert "FAMILYMARK_alpha" in values
    assert "CFGX::build=" in values                       # generalised prefix
    assert not any("CurrentVersion" in v for v in values)  # in goodware -> rejected
    assert stats["rejected"]["goodware_exact"] >= 1


def test_build_rules_compiles_without_decoded_strings():
    c = scoring.Candidate("FAMILYMARK_alpha", "static", {"ascii"}, {"s0", "s1"}, 1.0)
    c2 = scoring.Candidate("FAMILYMARK_beta", "static", {"ascii", "wide"}, {"s0", "s1"}, 1.0)
    built = yaragen.build_rules("Test Fam", [c, c2], [], [{"size": 1000, "type": "PE", "sha256": "0" * 64}], [], Config())
    assert "$x*" not in built["text"]
    yara.compile(source=built["text"])


def test_build_rules_empty_raises():
    with pytest.raises(ValueError):
        yaragen.build_rules("X", [], [], [{"size": 1, "type": "PE"}], [], Config())
