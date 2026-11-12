/*
 * AirBreak: нативная часть для команд в игровом чате.
 *
 * Это прокси-библиотека version.dll: игра загружает её вместо системной, она пересылает все вызовы
 * настоящей version.dll и дополнительно ставит хук на функцию игры Bindings_Chat::SendChatInput
 * (адрес ищется по сигнатуре, поэтому работает при смене базового адреса exe).
 *
 * Если текст в чате начинается с «/air», хук записывает его в файл %TEMP%\airbreak_chat.txt
 * и НЕ отправляет сообщение на сервер. Lua-мод AirBreak читает этот файл и выполняет команду.
 * Любое другое сообщение уходит как обычно.
 *
 * Состояние хука пишется в %TEMP%\airbreak_hook.log (мод AirBreak перепечатает его в UE4SS.log).
 *
 * Аргументы запуска: до старта движка подменяем GetCommandLineW в таблице импорта exe и дописываем
 * в конец командной строки аргументы (по умолчанию -FeatureLevelES31 и т.д.). Список можно поменять
 * файлом hassle_args.txt рядом с exe (одна строка = один аргумент или пара «-ключ значение»).
 * Сборка: Native\build.bat (нужен Visual Studio Build Tools, x64).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* ── пересылка экспорта настоящей version.dll ── */
#define FWD(n) __pragma(comment(linker, "/EXPORT:" #n "=C:\\Windows\\System32\\version." #n))
FWD(GetFileVersionInfoA)
FWD(GetFileVersionInfoByHandle)
FWD(GetFileVersionInfoExA)
FWD(GetFileVersionInfoExW)
FWD(GetFileVersionInfoSizeA)
FWD(GetFileVersionInfoSizeExA)
FWD(GetFileVersionInfoSizeExW)
FWD(GetFileVersionInfoSizeW)
FWD(GetFileVersionInfoW)
FWD(VerFindFileA)
FWD(VerFindFileW)
FWD(VerInstallFileA)
FWD(VerInstallFileW)
FWD(VerLanguageNameA)
FWD(VerLanguageNameW)
FWD(VerQueryValueA)
FWD(VerQueryValueW)

/* ── пути к файлам обмена ── */
static void temp_path(const wchar_t *name, wchar_t *out, size_t cap)
{
    wchar_t dir[MAX_PATH];
    DWORD n;
    size_t len;
    dir[0] = 0;
    n = GetEnvironmentVariableW(L"TEMP", dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) n = GetEnvironmentVariableW(L"TMP", dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) { dir[0] = 0; GetTempPathW(MAX_PATH, dir); }
    len = wcslen(dir);
    while (len > 0 && (dir[len - 1] == L'\\' || dir[len - 1] == L'/')) dir[--len] = 0;
    _snwprintf(out, cap, L"%ls\\%ls", dir, name);
    out[cap - 1] = 0;
}

static int append_file(const wchar_t *path, const void *buf, DWORD len)
{
    int attempt;
    for (attempt = 0; attempt < 5; attempt++) {
        HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(h, buf, len, &w, NULL);
            CloseHandle(h);
            return 1;
        }
        Sleep(2);
    }
    return 0;
}

static void hook_log(const char *fmt, ...)
{
    wchar_t path[MAX_PATH + 32];
    char line[600];
    int n;
    va_list ap;
    temp_path(L"airbreak_hook.log", path, sizeof(path) / sizeof(path[0]));
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(line) - 3) n = (int)sizeof(line) - 3;
    line[n++] = '\n';
    append_file(path, line, (DWORD)n);
}

/* ── перехват SendChatInput(UBindings_Chat* this, const FString& Text) ── */
typedef struct { wchar_t *Data; int Num; int Max; } FString;   /* Num включает завершающий ноль */
typedef void (__fastcall *SendChat_t)(void *self, FString *text);
static SendChat_t g_orig = NULL;
static wchar_t g_cmd_path[MAX_PATH + 32];

static int is_air_cmd(const FString *s)
{
    const wchar_t *t;
    if (!s || !s->Data || s->Num < 5) return 0;      /* "/air" + ноль = 5 */
    t = s->Data;
    if (t[0] != L'/') return 0;
    if ((t[1] | 0x20) != L'a' || (t[2] | 0x20) != L'i' || (t[3] | 0x20) != L'r') return 0;
    return t[4] == 0 || t[4] == L' ' || t[4] == L'\t';
}

static void emit_cmd(const FString *s)
{
    char utf8[1500];
    int wlen = s->Num - 1, n, i;
    if (wlen > 400) wlen = 400;
    n = WideCharToMultiByte(CP_UTF8, 0, s->Data, wlen, utf8, (int)sizeof(utf8) - 2, NULL, NULL);
    if (n <= 0) return;
    for (i = 0; i < n; i++) if (utf8[i] == '\r' || utf8[i] == '\n') utf8[i] = ' ';
    utf8[n++] = '\n';
    append_file(g_cmd_path, utf8, (DWORD)n);
}

static void __fastcall hook_send_chat(void *self, FString *text)
{
    if (is_air_cmd(text)) { emit_cmd(text); return; }   /* команда AirBreak: на сервер не отправляем */
    g_orig(self, text);
}


/* ── аргументы запуска (всегда добавляются к командной строке игры) ── */
static const wchar_t *DEFAULT_ARGS[] = {
    L"-FeatureLevelES31",    /* мобильный рендер на ПК: больше FPS */
    L"-SkipUpdatePaks",
    L"-c",
    L"-n shad0w",
    L"-s L",
    NULL
};
static wchar_t *g_cmdline = NULL;          /* итоговая командная строка (NULL — подмена не нужна) */

static LPWSTR WINAPI hook_GetCommandLineW(void)
{
    return g_cmdline;
}

/* есть ли в командной строке токен, совпадающий с первым словом аргумента (без учёта регистра) */
static int cmdline_has_key(const wchar_t *cmd, const wchar_t *arg)
{
    wchar_t key[128];
    size_t klen = 0;
    const wchar_t *p = cmd;
    while (arg[klen] && arg[klen] != L' ' && klen < 127) { key[klen] = arg[klen]; klen++; }
    key[klen] = 0;
    if (klen == 0) return 1;
    while (*p) {
        const wchar_t *start;
        size_t len;
        int quoted = 0;
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p) break;
        if (*p == L'"') { quoted = 1; p++; }
        start = p;
        while (*p && (quoted ? *p != L'"' : (*p != L' ' && *p != L'\t'))) p++;
        len = (size_t)(p - start);
        if (quoted && *p == L'"') p++;
        if (len == klen && _wcsnicmp(start, key, klen) == 0) return 1;
    }
    return 0;
}

/* читаем hassle_args.txt рядом с exe; возвращает выделенный массив строк или NULL, если файла нет */
static wchar_t **load_args_file(int *count)
{
    wchar_t path[MAX_PATH + 32];
    HANDLE h;
    DWORD size = 0, got = 0;
    char *buf;
    wchar_t **list;
    int n = 0, cap = 32;
    char *line, *end;
    size_t len;

    *count = 0;
    len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return NULL;
    while (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') len--;
    path[len] = 0;
    wcscat(path, L"hassle_args.txt");

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > 65536) { CloseHandle(h); return NULL; }
    buf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 2);
    list = (wchar_t **)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(wchar_t *) * cap);
    if (!buf || !list || !ReadFile(h, buf, size, &got, NULL)) { CloseHandle(h); return NULL; }
    CloseHandle(h);
    buf[got] = 0;

    line = buf;
    if ((unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF) line += 3;  /* BOM */
    while (*line && n < cap) {
        char *next;
        end = line;
        while (*end && *end != '\n' && *end != '\r') end++;
        next = *end ? end + 1 : end;
        *end = 0;
        while (*line == ' ' || *line == '\t') line++;
        while (end > line && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        if (*line && *line != '#') {
            int wl = MultiByteToWideChar(CP_UTF8, 0, line, -1, NULL, 0);
            if (wl > 0) {
                wchar_t *w = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(wchar_t) * wl);
                if (w) { MultiByteToWideChar(CP_UTF8, 0, line, -1, w, wl); list[n++] = w; }
            }
        }
        line = next;
    }
    *count = n;
    return list;
}

static void build_cmdline(void)
{
    const wchar_t *orig = GetCommandLineW();
    wchar_t **file_args;
    int file_count = 0, i, total_ct;
    size_t need;
    wchar_t *out;
    size_t pos;
    const wchar_t *def_ptrs[16];
    const wchar_t *const *args;

    if (!orig) return;
    file_args = load_args_file(&file_count);
    if (file_args) {
        args = (const wchar_t *const *)file_args;
        total_ct = file_count;
    } else {
        for (i = 0; DEFAULT_ARGS[i] && i < 15; i++) def_ptrs[i] = DEFAULT_ARGS[i];
        total_ct = i;
        args = def_ptrs;
    }

    need = wcslen(orig) + 1;
    for (i = 0; i < total_ct; i++) need += wcslen(args[i]) + 1;
    out = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need * sizeof(wchar_t));
    if (!out) return;
    wcscpy(out, orig);
    pos = wcslen(out);
    for (i = 0; i < total_ct; i++) {
        if (cmdline_has_key(orig, args[i])) continue;      /* уже передано при запуске — не дублируем */
        out[pos++] = L' ';
        wcscpy(out + pos, args[i]);
        pos += wcslen(args[i]);
    }
    out[pos] = 0;
    g_cmdline = out;
}

/* подмена GetCommandLineW в таблице импорта основного exe */
static int patch_getcmdline_iat(void)
{
    uint8_t *mod = (uint8_t *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(mod + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *imp;
    int patched = 0;

    if (!dd->VirtualAddress) return 0;
    imp = (IMAGE_IMPORT_DESCRIPTOR *)(mod + dd->VirtualAddress);
    __try {
        for (; imp->Name; imp++) {
            IMAGE_THUNK_DATA64 *oft = (IMAGE_THUNK_DATA64 *)(mod + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            IMAGE_THUNK_DATA64 *ft = (IMAGE_THUNK_DATA64 *)(mod + imp->FirstThunk);
            for (; oft->u1.AddressOfData; oft++, ft++) {
                IMAGE_IMPORT_BY_NAME *ibn;
                if (IMAGE_SNAP_BY_ORDINAL64(oft->u1.Ordinal)) continue;
                ibn = (IMAGE_IMPORT_BY_NAME *)(mod + oft->u1.AddressOfData);
                if (strcmp((const char *)ibn->Name, "GetCommandLineW") == 0) {
                    DWORD old = 0;
                    if (VirtualProtect(&ft->u1.Function, sizeof(ft->u1.Function), PAGE_READWRITE, &old)) {
                        ft->u1.Function = (ULONGLONG)(uintptr_t)&hook_GetCommandLineW;
                        VirtualProtect(&ft->u1.Function, sizeof(ft->u1.Function), old, &old);
                        patched++;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return patched;
}

static void apply_cmdline_args(void)
{
    build_cmdline();
    if (g_cmdline && !patch_getcmdline_iat()) g_cmdline = NULL;   /* не удалось подменить — оставляем как есть */
}

/* ── поиск функции по сигнатуре ── */
/* начало Bindings_Chat::SendChatInput: пролог + вызов проверки + «jne» на длинный переход */
static const char *SIG =
    "40 55 53 56 57 41 56 48 8D 6C 24 C9 48 81 EC 90 00 00 00 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? 84 C0 0F 85 0D 01 00 00";
/* первые 19 байт (целые инструкции) — их копируем в трамплин */
static const uint8_t PROLOGUE[19] = {
    0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x56, 0x48, 0x8D, 0x6C, 0x24, 0xC9, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00
};

static int parse_sig(const char *s, uint8_t *bytes, uint8_t *mask, int cap)
{
    int n = 0;
    while (*s && n < cap) {
        while (*s == ' ') s++;
        if (!*s) break;
        if (s[0] == '?') { bytes[n] = 0; mask[n] = 0; n++; s += 2; }
        else {
            unsigned v = 0;
            sscanf(s, "%2x", &v);
            bytes[n] = (uint8_t)v; mask[n] = 1; n++; s += 2;
        }
    }
    return n;
}

static uint8_t *scan_section(uint8_t *base, size_t size, const uint8_t *bytes, const uint8_t *mask, int n)
{
    size_t i;
    int k;
    __try {
        for (i = 0; i + (size_t)n <= size; i++) {
            if (base[i] != bytes[0]) continue;
            for (k = 1; k < n; k++) if (mask[k] && base[i + k] != bytes[k]) break;
            if (k == n) return base + i;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return NULL;
}

static uint8_t *find_pattern(void)
{
    uint8_t bytes[64], mask[64];
    int n = parse_sig(SIG, bytes, mask, 64), s;
    uint8_t *mod = (uint8_t *)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mod;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(mod + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (s = 0; s < nt->FileHeader.NumberOfSections; s++) {
        if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t *r = scan_section(mod + sec[s].VirtualAddress, sec[s].Misc.VirtualSize, bytes, mask, n);
            if (r) return r;
        }
    }
    return NULL;
}

static void write_abs_jmp(uint8_t *at, void *dst)   /* jmp [rip+0] ; dq dst  (14 байт) */
{
    at[0] = 0xFF; at[1] = 0x25;
    at[2] = at[3] = at[4] = at[5] = 0;
    memcpy(at + 6, &dst, 8);
}

static int install_hook(void)
{
    uint8_t *target = find_pattern();
    uint8_t *tramp;
    DWORD old = 0;
    if (!target) return 0;
    if (memcmp(target, PROLOGUE, sizeof(PROLOGUE)) != 0) { hook_log("сигнатура найдена, но пролог не совпал"); return -1; }
    tramp = (uint8_t *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) { hook_log("VirtualAlloc не удался (%lu)", GetLastError()); return -1; }
    memcpy(tramp, target, sizeof(PROLOGUE));
    write_abs_jmp(tramp + sizeof(PROLOGUE), target + sizeof(PROLOGUE));
    g_orig = (SendChat_t)(void *)tramp;
    if (!VirtualProtect(target, sizeof(PROLOGUE), PAGE_EXECUTE_READWRITE, &old)) {
        hook_log("VirtualProtect не удался (%lu)", GetLastError()); return -1;
    }
    write_abs_jmp(target, (void *)&hook_send_chat);
    memset(target + 14, 0x90, sizeof(PROLOGUE) - 14);
    VirtualProtect(target, sizeof(PROLOGUE), old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(PROLOGUE));
    hook_log("хук SendChatInput установлен: exe+0x%llX", (unsigned long long)(target - (uint8_t *)GetModuleHandleW(NULL)));
    return 1;
}

static DWORD WINAPI install_thread(LPVOID unused)
{
    int i, r = 0;
    wchar_t logp[MAX_PATH + 32];
    (void)unused;
    temp_path(L"airbreak_chat.txt", g_cmd_path, sizeof(g_cmd_path) / sizeof(g_cmd_path[0]));
    temp_path(L"airbreak_hook.log", logp, sizeof(logp) / sizeof(logp[0]));
    DeleteFileW(g_cmd_path);     /* старые команды от прошлого запуска не нужны */
    DeleteFileW(logp);
    hook_log("version.dll (AirBreak) загружена, ищу SendChatInput");
    if (g_cmdline) hook_log("командная строка с аргументами: %ls", g_cmdline);
    else hook_log("аргументы запуска не подменены (GetCommandLineW не найден в импорте exe)");
    for (i = 0; i < 90; i++) {
        r = install_hook();
        if (r != 0) break;
        Sleep(1000);
    }
    if (r == 0) hook_log("сигнатура SendChatInput не найдена (exe другой версии?) — команды в чате не будут работать");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t exe[MAX_PATH];
        size_t len;
        DisableThreadLibraryCalls(h);
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        len = wcslen(exe);
        if (len >= 12 && _wcsicmp(exe + len - 12, L"Shipping.exe") == 0) {   /* только в самой игре */
            HANDLE t;
            apply_cmdline_args();     /* до WinMain: движок прочитает уже готовую командную строку */
            t = CreateThread(NULL, 0, install_thread, NULL, 0, NULL);
            if (t) CloseHandle(t);
        }
    }
    return TRUE;
}
