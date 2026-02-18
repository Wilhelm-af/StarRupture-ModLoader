#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// ─── Function pointer array for assembly trampolines ─────────────────────────
// Defined here, referenced by trampolines.S via RIP-relative addressing.
// Index mapping matches the .def file (ExportName=fN @ordinal).
// Made by Wilhelm-af

#define NUM_EXPORTS 143

extern "C" uintptr_t mProcs[NUM_EXPORTS] = {0};

// ─── Logging (Windows API only, no CRT stdio) ───────────────────────────────

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static wchar_t g_dllDir[MAX_PATH] = {};

static void LogOpen() {
    wchar_t logPath[MAX_PATH];
    wsprintfW(logPath, L"%s\\modloader.log", g_dllDir);
    g_logFile = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

static void LogWrite(const char* buf, int len) {
    if (g_logFile == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(g_logFile, buf, len, &written, nullptr);
}

static void Log(const char* msg) {
    if (g_logFile == INVALID_HANDLE_VALUE) return;

    // Timestamp via Windows API
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[512];
    int n = wsprintfA(buf, "[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n",
                      st.wYear, st.wMonth, st.wDay,
                      st.wHour, st.wMinute, st.wSecond, msg);
    LogWrite(buf, n);
}

static void LogFmt(const char* prefix, const char* detail) {
    if (g_logFile == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[1024];
    int n = wsprintfA(buf, "[%04d-%02d-%02d %02d:%02d:%02d] %s%s\r\n",
                      st.wYear, st.wMonth, st.wDay,
                      st.wHour, st.wMinute, st.wSecond, prefix, detail);
    LogWrite(buf, n);
}

static void LogW(const char* prefix, const wchar_t* wstr) {
    if (g_logFile == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeBuf[64];
    int tn = wsprintfA(timeBuf, "[%04d-%02d-%02d %02d:%02d:%02d] %s",
                       st.wYear, st.wMonth, st.wDay,
                       st.wHour, st.wMinute, st.wSecond, prefix);
    LogWrite(timeBuf, tn);

    // Convert wide string to UTF-8 for log
    char narrow[MAX_PATH * 2];
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, narrow, sizeof(narrow), nullptr, nullptr);
    if (len > 1) LogWrite(narrow, len - 1); // exclude null
    LogWrite("\r\n", 2);
}

static void LogErr(const char* prefix, DWORD err) {
    char buf[256];
    int n = wsprintfA(buf, "%s (error %lu)", prefix, err);
    buf[n] = '\0';
    Log(buf);
}

// ─── Load real dwmapi.dll and populate mProcs[] ─────────────────────────────

static HMODULE g_realDwmapi = nullptr;

// Named exports: {mProcs index, function name}
static const struct { int idx; const char* name; } g_namedExports[] = {
    { 0, "DwmpDxGetWindowSharedSurface"},
    { 1, "DwmpDxUpdateWindowSharedSurface"},
    { 2, "DwmEnableComposition"},
    { 3, "DllCanUnloadNow"},
    { 4, "DllGetClassObject"},
    { 5, "DwmAttachMilContent"},
    { 6, "DwmDefWindowProc"},
    { 7, "DwmDetachMilContent"},
    { 8, "DwmEnableBlurBehindWindow"},
    { 9, "DwmEnableMMCSS"},
    {10, "DwmExtendFrameIntoClientArea"},
    {11, "DwmFlush"},
    {12, "DwmGetColorizationColor"},
    {13, "DwmGetCompositionTimingInfo"},
    {14, "DwmGetGraphicsStreamClient"},
    {15, "DwmpGetColorizationParameters"},
    {16, "DwmpDxgiIsThreadDesktopComposited"},
    {17, "DwmGetGraphicsStreamTransformHint"},
    {18, "DwmGetTransportAttributes"},
    {19, "DwmpSetColorizationParameters"},
    {20, "DwmGetUnmetTabRequirements"},
    {21, "DwmGetWindowAttribute"},
    {22, "DwmpRenderFlick"},
    {23, "DwmpAllocateSecurityDescriptor"},
    {24, "DwmpFreeSecurityDescriptor"},
    {25, "DwmpEnableDDASupport"},
    {26, "DwmInvalidateIconicBitmaps"},
    {27, "DwmTetherTextContact"},
    {28, "DwmpUpdateProxyWindowForCapture"},
    {29, "DwmIsCompositionEnabled"},
    {30, "DwmModifyPreviousDxFrameDuration"},
    {31, "DwmQueryThumbnailSourceSize"},
    {32, "DwmRegisterThumbnail"},
    {33, "DwmRenderGesture"},
    {34, "DwmSetDxFrameDuration"},
    {35, "DwmSetIconicLivePreviewBitmap"},
    {36, "DwmSetIconicThumbnail"},
    {37, "DwmSetPresentParameters"},
    {38, "DwmSetWindowAttribute"},
    {39, "DwmShowContact"},
    {40, "DwmTetherContact"},
    {41, "DwmTransitionOwnedWindow"},
    {42, "DwmUnregisterThumbnail"},
    {43, "DwmUpdateThumbnailProperties"},
};

static bool LoadRealDwmapi() {
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    wchar_t realPath[MAX_PATH];
    wsprintfW(realPath, L"%s\\dwmapi.dll", sysDir);

    g_realDwmapi = LoadLibraryW(realPath);
    if (!g_realDwmapi) {
        Log("FATAL: Failed to load real dwmapi.dll from system directory");
        return false;
    }

    // Resolve named exports by name
    for (int i = 0; i < (int)(sizeof(g_namedExports) / sizeof(g_namedExports[0])); i++) {
        mProcs[g_namedExports[i].idx] =
            (uintptr_t)GetProcAddress(g_realDwmapi, g_namedExports[i].name);
    }

    // Resolve ordinal-only exports 100-198 (mProcs indices 44-142)
    for (int ord = 100; ord <= 198; ord++) {
        mProcs[44 + (ord - 100)] =
            (uintptr_t)GetProcAddress(g_realDwmapi, MAKEINTRESOURCEA(ord));
    }

    return true;
}

// ─── Simple JSON helpers (no std::string, no CRT) ───────────────────────────

// Find needle in haystack (minimal strstr replacement using only KERNEL32)
static const char* FindStr(const char* haystack, const char* needle) {
    for (; *haystack; haystack++) {
        const char* h = haystack;
        const char* n = needle;
        while (*n && *h == *n) { h++; n++; }
        if (!*n) return haystack;
    }
    return nullptr;
}

static bool JsonGetString(const char* json, const char* key, char* out, int outSize) {
    // Build "key" needle
    char needle[256];
    int nLen = wsprintfA(needle, "\"%s\"", key);

    const char* pos = FindStr(json, needle);
    if (!pos) { out[0] = '\0'; return false; }
    pos += nLen;
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':')) pos++;
    if (*pos != '"') { out[0] = '\0'; return false; }
    pos++;
    int i = 0;
    while (*pos && *pos != '"' && i < outSize - 1) {
        if (*pos == '\\' && *(pos + 1)) pos++;
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return i > 0;
}

static bool JsonGetBool(const char* json, const char* key, bool defaultVal) {
    char needle[256];
    int nLen = wsprintfA(needle, "\"%s\"", key);

    const char* pos = FindStr(json, needle);
    if (!pos) return defaultVal;
    pos += nLen;
    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ':')) pos++;

    // Compare manually (no strncmp needed)
    if (pos[0]=='f' && pos[1]=='a' && pos[2]=='l' && pos[3]=='s' && pos[4]=='e') return false;
    if (pos[0]=='t' && pos[1]=='r' && pos[2]=='u' && pos[3]=='e') return true;
    return defaultVal;
}

// ─── Mod Loading ─────────────────────────────────────────────────────────────

static void LoadMods() {
    wchar_t modsPath[MAX_PATH];
    wsprintfW(modsPath, L"%s\\Mods", g_dllDir);

    CreateDirectoryW(modsPath, nullptr);
    LogW("Mods directory: ", modsPath);

    int modsLoaded = 0;

    // Scan for root-level DLLs
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
                    LogErr("  Error code", GetLastError());
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // Scan subfolders for mod.json
    {
        wchar_t searchPath[MAX_PATH];
        wsprintfW(searchPath, L"%s\\*", modsPath);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (fd.cFileName[0] == L'.' && (fd.cFileName[1] == L'\0' ||
                    (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0'))) continue;

                wchar_t modJsonPath[MAX_PATH];
                wsprintfW(modJsonPath, L"%s\\%s\\mod.json", modsPath, fd.cFileName);

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

                // Allocate with HeapAlloc (no CRT malloc)
                char* jsonBuf = (char*)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
                if (!jsonBuf) {
                    CloseHandle(hFile);
                    continue;
                }
                DWORD bytesRead = 0;
                ReadFile(hFile, jsonBuf, fileSize, &bytesRead, nullptr);
                CloseHandle(hFile);
                jsonBuf[bytesRead] = '\0';

                char dllName[MAX_PATH];
                char modName[MAX_PATH];
                JsonGetString(jsonBuf, "dll", dllName, sizeof(dllName));
                bool hasName = JsonGetString(jsonBuf, "name", modName, sizeof(modName));
                bool enabled = JsonGetBool(jsonBuf, "enabled", true);
                HeapFree(GetProcessHeap(), 0, jsonBuf);

                if (dllName[0] == '\0') {
                    LogW("mod.json missing 'dll' field, skipping: ", fd.cFileName);
                    continue;
                }

                if (!hasName) {
                    WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, modName, MAX_PATH, nullptr, nullptr);
                }

                if (!enabled) {
                    LogFmt("Skipping disabled mod: ", modName);
                    continue;
                }

                wchar_t dllPath[MAX_PATH];
                wchar_t dllNameW[MAX_PATH];
                MultiByteToWideChar(CP_UTF8, 0, dllName, -1, dllNameW, MAX_PATH);
                wsprintfW(dllPath, L"%s\\%s\\%s", modsPath, fd.cFileName, dllNameW);

                LogFmt("Loading mod: ", modName);
                LogW("  DLL: ", dllPath);

                HMODULE hMod = LoadLibraryW(dllPath);
                if (hMod) {
                    LogFmt("Mod loaded successfully: ", modName);
                    modsLoaded++;
                } else {
                    char errBuf[512];
                    wsprintfA(errBuf, "FAILED to load mod: %s (error %lu)", modName, GetLastError());
                    Log(errBuf);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    char buf[128];
    wsprintfA(buf, "Mod loader ready: %d mod(s) loaded", modsLoaded);
    Log(buf);
}

// ─── DllMain ─────────────────────────────────────────────────────────────────

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        wchar_t dllPath[MAX_PATH];
        GetModuleFileNameW(hinstDLL, dllPath, MAX_PATH);
        wchar_t* lastSlash = dllPath;
        for (wchar_t* p = dllPath; *p; p++) {
            if (*p == L'\\') lastSlash = p;
        }
        *lastSlash = L'\0';
        // Copy to g_dllDir
        for (int i = 0; i < MAX_PATH; i++) {
            g_dllDir[i] = dllPath[i];
            if (!dllPath[i]) break;
        }

        LogOpen();
        Log("dwmapi.dll proxy loaded");

        if (!LoadRealDwmapi()) {
            return FALSE;
        }
        Log("Real dwmapi.dll loaded successfully");

        LoadMods();
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_logFile != INVALID_HANDLE_VALUE) {
            Log("dwmapi.dll proxy unloading");
            CloseHandle(g_logFile);
            g_logFile = INVALID_HANDLE_VALUE;
        }
        if (g_realDwmapi) {
            FreeLibrary(g_realDwmapi);
            g_realDwmapi = nullptr;
        }
    }
    return TRUE;
}
