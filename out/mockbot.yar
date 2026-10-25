import "pe"

rule MockBot_Strings
{
    meta:
        description = "Detects MockBot family samples (auto-generated, strings rule)"
        author = "yaraforge"
        date = "2026-10-25"
        family = "MockBot"
        generator = "yaraforge 1.0.0"
        sample_count = 8
        attack = "T1071.001, T1027, T1140, T1480, T1622, T1012, T1547.001"
        hash1 = "b775b6c06a70504470230e77bdbe09d240844fe7b9dfe13345cb2aeb1b68795b"
        hash2 = "b34a482c7b94faff6195575cb714d400b074c9c718444ae5cea9ab033b0eb66a"

    strings:
        $s1 = "[MockBot harmless lab sample] cfg=%s tag=%s junk=%u" ascii  // cov=1.00 src=static ioc=config_marker
        $s2 = "Mozilla/4.0 (compatible; MkBot/2.1; lab)" ascii  // cov=0.88 src=static ioc=user_agent
        $s3 = "MKBCFG::v2::build=" ascii  // cov=1.00 src=prefix ioc=config_marker
        $s4 = "Global\\MkB_7f3a9c21" ascii  // cov=0.88 src=static ioc=mutex
        $s5 = "mutex=%d run=%d net=%d (no network activity performed)" ascii  // cov=1.00 src=static
        $x6 = "http://c2.mockbot.invalid/gate.php?id=" xor(0x01-0xff)  // cov=0.50 src=decoded ioc=url

    condition:
        uint16(0) == 0x5A4D and filesize < 85KB and
        3 of ($s*, $x*)
}

rule MockBot_Imports_Baseline
{
    meta:
        description = "MockBot API-only baseline - for comparison, NOT for deployment"
        author = "yaraforge"
        date = "2026-10-25"
        quality = "low"

    condition:
        uint16(0) == 0x5A4D and
        pe.imports(/kernel32\.dll/i, /^createmutexa$/i) and
        pe.imports(/wininet\.dll/i, /^internetopena$/i) and
        pe.imports(/advapi32\.dll/i, /^regopenkeyexa$/i) and
        pe.imports(/wininet\.dll/i, /^internetclosehandle$/i)
}
