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
        hash1 = "4c2830767b00ecf9dae072dfe1e6e58b4a575e5a0f5f86b134da2d574beed826"
        hash2 = "b61828f632ff5a0b3324f5c218cba45529eb79e1da9e3dba2460dbe849fc2da9"

    strings:
        $s1 = "Mozilla/4.0 (compatible; MkBot/2.1; lab)" ascii  // cov=0.88 src=static ioc=user_agent
        $s2 = "MKBCFG::v2::build=" ascii  // cov=1.00 src=prefix ioc=config_marker
        $s3 = "Global\\MkB_7f3a9c21" ascii  // cov=0.88 src=static ioc=mutex
        $s4 = "mutex=%d run=%d net=%d (no network activity performed)" ascii  // cov=1.00 src=static
        $s5 = "[MockBot harmless lab sample] cfg=%s tag=%s junk=%u" ascii  // cov=0.62 src=static ioc=config_marker
        $s6 = "http://c2.mockbot.invalid/gate." ascii  // cov=0.50 src=prefix ioc=url
        $s7 = "MkB_loadH" ascii  // cov=0.50 src=static

    condition:
        uint16(0) == 0x5A4D and filesize < 165KB and
        4 of ($s*)
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
        pe.imports(/api\-ms\-win\-crt\-string\-l1\-1\-0\.dll/i, /^strcpy$/i) and
        pe.imports(/wininet\.dll/i, /^internetclosehandle$/i) and
        pe.imports(/wininet\.dll/i, /^internetopena$/i) and
        pe.imports(/kernel32\.dll/i, /^createmutexa$/i)
}
