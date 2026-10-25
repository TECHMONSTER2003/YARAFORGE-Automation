/*
 * MockBot - HARMLESS simulated "malware family" for YARA lab testing.
 *
 * This program performs NO malicious action. It only:
 *   - creates and immediately closes a named mutex
 *   - opens (read-only) and closes the HKCU Run key
 *   - initialises and closes a WinINet handle (no connection is made)
 *   - XOR-decodes a placeholder URL on a reserved .invalid domain (RFC 2606)
 *     into a local buffer that is never used for networking
 *
 * Purpose: give the static pipeline (pefile / FLOSS / capa / YARA) a
 * reproducible "family" whose members share genuine family traits
 * (mutex, config marker, user agent, encoded C2 string) while differing
 * in compiler flags, architecture, junk data and code layout - the same
 * situation an analyst faces with real builder-generated malware.
 *
 * Placeholders substituted by build_corpus.py:
 *   @@MUTEX@@  @@UA@@  @@CFG@@  @@JUNK@@  @@XORKEY@@  @@ENC_C2@@  @@ENC_LEN@@
 */
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string.h>

/* family trait: configuration marker + build tag */
static const char g_cfg[]   = "@@CFG@@";
/* family trait: hard-coded user agent */
static const char g_ua[]    = "@@UA@@";
/* family trait: persistence location (also used by many legit apps) */
static const char g_runkey[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
/* per-build junk (simulates builder randomisation) */
static const char *g_junk[] = { @@JUNK@@ };

/* family trait: XOR-obfuscated C2 URL (FLOSS should recover this) */
static unsigned char g_enc_c2[] = { @@ENC_C2@@ };

static void mk_decode(unsigned char *dst, const unsigned char *src, size_t n, unsigned char k)
{
    size_t i;
    for (i = 0; i < n; i++)
        dst[i] = src[i] ^ k;
    dst[n] = 0;
}

/* family trait: stack-built string (FLOSS stack-string recovery) */
static void mk_stack_tag(char *out)
{
    char t[12];
    t[0]='M'; t[1]='k'; t[2]='B'; t[3]='_'; t[4]='l'; t[5]='o';
    t[6]='a'; t[7]='d'; t[8]='e'; t[9]='r'; t[10]=0;
    strcpy(out, t);
}

static int mk_single_instance(void)
{
    HANDLE h = CreateMutexA(NULL, FALSE, "@@MUTEX@@");
    if (h) CloseHandle(h);
    return h != NULL;
}

static int mk_probe_persistence(void)
{
    HKEY k;
    LONG r = RegOpenKeyExA(HKEY_CURRENT_USER, g_runkey, 0, KEY_READ, &k);
    if (r == ERROR_SUCCESS) RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static int mk_net_init(void)
{
    HINTERNET h = InternetOpenA(g_ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (h) InternetCloseHandle(h);   /* no connection is ever made */
    return h != NULL;
}

int main(int argc, char **argv)
{
    unsigned char c2[256];
    char tag[16];
    volatile size_t junk_n = sizeof(g_junk) / sizeof(g_junk[0]);

    (void)argv;
    if (IsDebuggerPresent())          /* anti-analysis trait, harmless */
        return 0;

    mk_decode(c2, g_enc_c2, @@ENC_LEN@@, @@XORKEY@@);
    mk_stack_tag(tag);

    printf("[MockBot harmless lab sample] cfg=%s tag=%s junk=%u\n",
           g_cfg, tag, (unsigned)junk_n);
    printf("mutex=%d run=%d net=%d (no network activity performed)\n",
           mk_single_instance(), mk_probe_persistence(), mk_net_init());
    if (argc > 99) puts((char *)c2); /* never true in practice */
    return 0;
}
