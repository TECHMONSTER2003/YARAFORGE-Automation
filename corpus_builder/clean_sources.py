"""Benign C programs used as the goodware (clean) corpus.

`nearmiss_updater` deliberately uses the SAME Windows APIs as MockBot
(mutex, Run key, WinINet, IsDebuggerPresent) with different strings.
An import-only YARA rule will false-positive on it; a well-scored
string rule must not. This is the key negative control of the project.
"""

CLEAN_PROGRAMS = {
    "hello": r'''
#include <stdio.h>
int main(void){ puts("Hello from a clean test program"); return 0; }
''',
    "checksum": r'''
#include <stdio.h>
#include <stdint.h>
static uint32_t adler32(const unsigned char *d, size_t n){
    uint32_t a = 1, b = 0; size_t i;
    for (i = 0; i < n; i++){ a = (a + d[i]) % 65521; b = (b + a) % 65521; }
    return (b << 16) | a;
}
int main(int argc, char **argv){
    FILE *f; unsigned char buf[4096]; size_t n; uint32_t c = 0;
    if (argc < 2){ puts("usage: checksum <file>"); return 1; }
    f = fopen(argv[1], "rb"); if (!f){ perror("open"); return 1; }
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) c ^= adler32(buf, n);
    fclose(f); printf("adler-xor: %08x\n", c); return 0;
}
''',
    "filecopy": r'''
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv){
    if (argc < 3){ puts("usage: filecopy <src> <dst>"); return 1; }
    if (!CopyFileA(argv[1], argv[2], TRUE)){ printf("CopyFile failed: %lu\n", GetLastError()); return 1; }
    puts("copied"); return 0;
}
''',
    "sysinfo": r'''
#include <windows.h>
#include <stdio.h>
int main(void){
    SYSTEM_INFO si; MEMORYSTATUSEX ms; char name[MAX_COMPUTERNAME_LENGTH + 1]; DWORD n = sizeof name;
    GetSystemInfo(&si); ms.dwLength = sizeof ms; GlobalMemoryStatusEx(&ms);
    GetComputerNameA(name, &n);
    printf("host=%s cpus=%lu mem=%llu MB\n", name, si.dwNumberOfProcessors, ms.ullTotalPhys >> 20);
    return 0;
}
''',
    "nearmiss_updater": r'''
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
/* Legitimate-style auto-updater: same API surface as MockBot. */
int main(void){
    HKEY k; HINTERNET h; HANDLE m;
    if (IsDebuggerPresent()) puts("debug build");
    m = CreateMutexA(NULL, FALSE, "Local\\ContosoUpdaterSingleInstance");
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &k) == ERROR_SUCCESS)
        RegCloseKey(k);
    h = InternetOpenA("ContosoUpdater/3.4 (+https://contoso.example/update)",
                      INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (h) InternetCloseHandle(h);
    if (m) CloseHandle(m);
    puts("Contoso updater: no updates available");
    return 0;
}
''',
}
