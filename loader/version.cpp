#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <string>

// ─── Logging ─────────────────────────────────────────────────────────────────

static FILE* g_logFile = nullptr;
static wchar_t g_dllDir[MAX_PATH] = {};

static void LogOpen() {
    wchar_t logPath[MAX_PATH];
    wsprintfW(logPath, L"%s\\modloader.log", g_dllDir);
    g_logFile = _wfopen(logPath, L"w");
}

static void Log(const char* fmt, ...) {
    if (!g_logFile) return;

    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    fprintf(g_logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);

    fprintf(g_logFile, "\n");
    fflush(g_logFile);
}

static void LogW(const char* prefix, const wchar_t* wstr) {
    if (!g_logFile) return;

    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    fprintf(g_logFile, "[%04d-%02d-%02d %02d:%02d:%02d] %s",
            t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
            t.tm_hour, t.tm_min, t.tm_sec, prefix);
    fwprintf(g_logFile, L"%s\n", wstr);
    fflush(g_logFile);
}

// ─── Proxy Exports ──────────────────────────────────────────────────────────

static HMODULE g_realVersion = nullptr;

#define PROXY_FUNC(name) \
    static decltype(&name) p_##name = nullptr;

// Declare function pointer for each export
// We use void* and GetProcAddress since some of these aren't declared in all SDK headers
typedef void* PROXY_PTR;
static PROXY_PTR p_GetFileVersionInfoA = nullptr;
static PROXY_PTR p_GetFileVersionInfoByHandle = nullptr;
static PROXY_PTR p_GetFileVersionInfoExA = nullptr;
static PROXY_PTR p_GetFileVersionInfoExW = nullptr;
static PROXY_PTR p_GetFileVersionInfoSizeA = nullptr;
static PROXY_PTR p_GetFileVersionInfoSizeExA = nullptr;
static PROXY_PTR p_GetFileVersionInfoSizeExW = nullptr;
static PROXY_PTR p_GetFileVersionInfoSizeW = nullptr;
static PROXY_PTR p_GetFileVersionInfoW = nullptr;
static PROXY_PTR p_VerFindFileA = nullptr;
static PROXY_PTR p_VerFindFileW = nullptr;
static PROXY_PTR p_VerInstallFileA = nullptr;
static PROXY_PTR p_VerInstallFileW = nullptr;
static PROXY_PTR p_VerLanguageNameA = nullptr;
static PROXY_PTR p_VerLanguageNameW = nullptr;
static PROXY_PTR p_VerQueryValueA = nullptr;
static PROXY_PTR p_VerQueryValueW = nullptr;

static bool LoadRealVersion() {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t realPath[MAX_PATH];
    wsprintfW(realPath, L"%s\\version.dll", sysDir);

    g_realVersion = LoadLibraryW(realPath);
    if (!g_realVersion) {
        Log("FATAL: Failed to load real version.dll");
        return false;
    }

    #define RESOLVE(name) p_##name = (PROXY_PTR)GetProcAddress(g_realVersion, #name)

    RESOLVE(GetFileVersionInfoA);
    RESOLVE(GetFileVersionInfoByHandle);
    RESOLVE(GetFileVersionInfoExA);
    RESOLVE(GetFileVersionInfoExW);
    RESOLVE(GetFileVersionInfoSizeA);
    RESOLVE(GetFileVersionInfoSizeExA);
    RESOLVE(GetFileVersionInfoSizeExW);
    RESOLVE(GetFileVersionInfoSizeW);
    RESOLVE(GetFileVersionInfoW);
    RESOLVE(VerFindFileA);
    RESOLVE(VerFindFileW);
    RESOLVE(VerInstallFileA);
    RESOLVE(VerInstallFileW);
    RESOLVE(VerLanguageNameA);
    RESOLVE(VerLanguageNameW);
    RESOLVE(VerQueryValueA);
    RESOLVE(VerQueryValueW);

    #undef RESOLVE
    return true;
}

// ─── Exported proxy stubs ────────────────────────────────────────────────────
// Each export jumps to the real function. We use naked asm or __declspec
// to ensure the calling convention is preserved.
// For MinGW cross-compilation, we use simple wrapper approach.

// Generic proxy macro: forward all args via the pointer
// These are all stdcall/cdecl functions — we use a trampoline approach.
// Since we can't easily do naked functions in x86_64 MinGW, we use
// a typedef + cast approach for each function.

extern "C" {

// GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID) -> BOOL
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *fn_t)(LPCSTR, DWORD, DWORD, LPVOID);
    return ((fn_t)p_GetFileVersionInfoA)(lptstrFilename, dwHandle, dwLen, lpData);
}

// GetFileVersionInfoByHandle - undocumented, takes varied params, use generic forwarder
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoByHandle(DWORD a, HANDLE b, LPVOID c, DWORD d) {
    typedef BOOL (WINAPI *fn_t)(DWORD, HANDLE, LPVOID, DWORD);
    if (!p_GetFileVersionInfoByHandle) return FALSE;
    return ((fn_t)p_GetFileVersionInfoByHandle)(a, b, c, d);
}

// GetFileVersionInfoExA(DWORD, LPCSTR, DWORD, DWORD, LPVOID) -> BOOL
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *fn_t)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    return ((fn_t)p_GetFileVersionInfoExA)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *fn_t)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    return ((fn_t)p_GetFileVersionInfoExW)(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *fn_t)(LPCSTR, LPDWORD);
    return ((fn_t)p_GetFileVersionInfoSizeA)(lptstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPCSTR, LPDWORD);
    return ((fn_t)p_GetFileVersionInfoSizeExA)(dwFlags, lpwstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPCWSTR, LPDWORD);
    return ((fn_t)p_GetFileVersionInfoSizeExW)(dwFlags, lpwstrFilename, lpdwHandle);
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *fn_t)(LPCWSTR, LPDWORD);
    return ((fn_t)p_GetFileVersionInfoSizeW)(lptstrFilename, lpdwHandle);
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *fn_t)(LPCWSTR, DWORD, DWORD, LPVOID);
    return ((fn_t)p_GetFileVersionInfoW)(lptstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport) DWORD WINAPI VerFindFileA(DWORD uFlags, LPSTR szFileName, LPSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, PUINT, LPSTR, PUINT);
    return ((fn_t)p_VerFindFileA)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

__declspec(dllexport) DWORD WINAPI VerFindFileW(DWORD uFlags, LPWSTR szFileName, LPWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    return ((fn_t)p_VerFindFileW)(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen);
}

__declspec(dllexport) DWORD WINAPI VerInstallFileA(DWORD uFlags, LPSTR szSrcFileName, LPSTR szDestFileName, LPSTR szSrcDir, LPSTR szDestDir, LPSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, LPSTR, PUINT);
    return ((fn_t)p_VerInstallFileA)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

__declspec(dllexport) DWORD WINAPI VerInstallFileW(DWORD uFlags, LPWSTR szSrcFileName, LPWSTR szDestFileName, LPWSTR szSrcDir, LPWSTR szDestDir, LPWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, LPWSTR, PUINT);
    return ((fn_t)p_VerInstallFileW)(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen);
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPSTR, DWORD);
    return ((fn_t)p_VerLanguageNameA)(wLang, szLang, cchLang);
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    typedef DWORD (WINAPI *fn_t)(DWORD, LPWSTR, DWORD);
    return ((fn_t)p_VerLanguageNameW)(wLang, szLang, cchLang);
}

__declspec(dllexport) BOOL WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL (WINAPI *fn_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    return ((fn_t)p_VerQueryValueA)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen) {
    typedef BOOL (WINAPI *fn_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    return ((fn_t)p_VerQueryValueW)(pBlock, lpSubBlock, lplpBuffer, puLen);
}

} // extern "C"

// ─── Mod Loading ─────────────────────────────────────────────────────────────

// Simple JSON value extractor — no full parser needed
static std::string JsonGetString(const char* json, const char* key) {
    // Find "key" : "value"
    std::string needle = std::string("\"") + key + "\"";
    const char* pos = strstr(json, needle.c_str());
    if (!pos) return "";

    pos += needle.size();
    // Skip whitespace and colon
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':')) pos++;
    if (*pos != '"') return "";
    pos++; // skip opening quote

    std::string result;
    while (*pos && *pos != '"') {
        if (*pos == '\\' && *(pos + 1)) {
            pos++; // skip escape
        }
        result += *pos++;
    }
    return result;
}

static bool JsonGetBool(const char* json, const char* key, bool defaultVal) {
    std::string needle = std::string("\"") + key + "\"";
    const char* pos = strstr(json, needle.c_str());
    if (!pos) return defaultVal;

    pos += needle.size();
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':')) pos++;

    if (strncmp(pos, "false", 5) == 0) return false;
    if (strncmp(pos, "true", 4) == 0) return true;
    return defaultVal;
}

static void LoadMods() {
    wchar_t modsPath[MAX_PATH];
    wsprintfW(modsPath, L"%s\\Mods", g_dllDir);

    // Create Mods/ if it doesn't exist
    CreateDirectoryW(modsPath, nullptr);
    LogW("Mods directory: ", modsPath);

    int modsLoaded = 0;

    // ── Scan for root-level DLLs ──
    {
        wchar_t searchPath[MAX_PATH];
        wsprintfW(searchPath, L"%s\\*.dll", modsPath);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                wchar_t dllPath[MAX_PATH];
                wsprintfW(dllPath, L"%s\\%s", modsPath, fd.cFileName);

                HMODULE hMod = LoadLibraryW(dllPath);
                if (hMod) {
                    LogW("Loaded root mod: ", fd.cFileName);
                    modsLoaded++;
                } else {
                    LogW("FAILED to load root mod: ", fd.cFileName);
                    Log("  Error code: %lu", GetLastError());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // ── Scan subfolders for mod.json ──
    {
        wchar_t searchPath[MAX_PATH];
        wsprintfW(searchPath, L"%s\\*", modsPath);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                // Skip . and .. and non-directories
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                wchar_t modJsonPath[MAX_PATH];
                wsprintfW(modJsonPath, L"%s\\%s\\mod.json", modsPath, fd.cFileName);

                // Try to read mod.json
                HANDLE hFile = CreateFileW(modJsonPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hFile == INVALID_HANDLE_VALUE) {
                    LogW("Subfolder has no mod.json, skipping: ", fd.cFileName);
                    continue;
                }

                DWORD fileSize = GetFileSize(hFile, nullptr);
                if (fileSize == 0 || fileSize > 65536) {
                    CloseHandle(hFile);
                    LogW("Invalid mod.json size, skipping: ", fd.cFileName);
                    continue;
                }

                char* jsonBuf = new char[fileSize + 1];
                DWORD bytesRead = 0;
                ReadFile(hFile, jsonBuf, fileSize, &bytesRead, nullptr);
                CloseHandle(hFile);
                jsonBuf[bytesRead] = '\0';

                // Parse mod.json
                std::string dllName = JsonGetString(jsonBuf, "dll");
                std::string modName = JsonGetString(jsonBuf, "name");
                bool enabled = JsonGetBool(jsonBuf, "enabled", true);
                delete[] jsonBuf;

                if (dllName.empty()) {
                    LogW("mod.json missing 'dll' field, skipping: ", fd.cFileName);
                    continue;
                }

                if (modName.empty()) {
                    // Use folder name as display name
                    char folderNameA[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, folderNameA, MAX_PATH, nullptr, nullptr);
                    modName = folderNameA;
                }

                if (!enabled) {
                    Log("Skipping disabled mod: %s", modName.c_str());
                    continue;
                }

                // Build DLL path
                wchar_t dllPath[MAX_PATH];
                wchar_t dllNameW[MAX_PATH];
                MultiByteToWideChar(CP_UTF8, 0, dllName.c_str(), -1, dllNameW, MAX_PATH);
                wsprintfW(dllPath, L"%s\\%s\\%s", modsPath, fd.cFileName, dllNameW);

                Log("Loading mod: %s", modName.c_str());
                LogW("  DLL: ", dllPath);

                HMODULE hMod = LoadLibraryW(dllPath);
                if (hMod) {
                    Log("Mod loaded successfully: %s", modName.c_str());
                    modsLoaded++;
                } else {
                    Log("FAILED to load mod: %s (error %lu)", modName.c_str(), GetLastError());
                }

            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    Log("Mod loader ready: %d mod(s) loaded", modsLoaded);
}

// ─── DllMain ─────────────────────────────────────────────────────────────────

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        // Get our DLL's directory
        wchar_t dllPath[MAX_PATH];
        GetModuleFileNameW(hinstDLL, dllPath, MAX_PATH);
        // Strip filename to get directory
        wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
        if (lastSlash) *lastSlash = L'\0';
        wcscpy(g_dllDir, dllPath);

        LogOpen();
        Log("version.dll proxy loaded");

        if (!LoadRealVersion()) {
            return FALSE;
        }
        Log("Real version.dll loaded successfully");

        LoadMods();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_logFile) {
            Log("version.dll proxy unloading");
            fclose(g_logFile);
            g_logFile = nullptr;
        }
        if (g_realVersion) {
            FreeLibrary(g_realVersion);
            g_realVersion = nullptr;
        }
    }
    return TRUE;
}
