/*
 * AirBreak: нативная часть для команд в игровом чате.
 *
 * Это прокси-библиотека version.dll: игра загружает её вместо системной, она пересылает все вызовы
 * настоящей version.dll и дополнительно ставит хук на функцию игры Bindings_Chat::SendChatInput
 * (адрес ищется по сигнатуре, поэтому работает при смене базового адреса exe).
 *
 * Если текст в чате начинается с «/air», хук записывает его в файл %TEMP%\airbreak_chat.txt,
 * а если с «/vtune» — в %TEMP%\vtune_chat.txt, и НЕ отправляет сообщение на сервер.
 * Lua-моды AirBreak и VTune читают свои файлы и выполняют команды.
 * Любое другое сообщение уходит как обычно.
 *
 * /vtune probe (запрос от Lua-мода VTune) запускает поиск структуры хендлинга за указателями, отчёт — vtune_probe.txt
 * рядом с exe (только чтение памяти).
 * /vtune tbl … — прямая правка таблицы хендлингов в памяти (см. блок TBL ниже), список записей — vtune_tbl.txt.
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
#include <stdlib.h>

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
/* маршруты команд чата: «/имя» -> файл в %TEMP%, который читает соответствующий Lua-мод */
typedef struct { const wchar_t *cmd; const wchar_t *file; wchar_t path[MAX_PATH + 32]; } ChatRoute;
static ChatRoute g_routes[] = {
    { L"air",   L"airbreak_chat.txt", { 0 } },
    { L"vtune", L"vtune_chat.txt",    { 0 } },
};
#define NROUTES ((int)(sizeof(g_routes) / sizeof(g_routes[0])))

/* текст = «/cmd» или «/cmd <что-то>» (без учёта регистра) */
static int is_route_cmd(const FString *s, const wchar_t *cmd)
{
    const wchar_t *t;
    size_t n = wcslen(cmd), k;
    if (!s || !s->Data || (size_t)s->Num < n + 2) return 0;     /* «/» + имя + ноль */
    t = s->Data;
    if (t[0] != L'/') return 0;
    for (k = 0; k < n; k++) if ((t[1 + k] | 0x20) != (cmd[k] | 0x20)) return 0;
    return t[1 + n] == 0 || t[1 + n] == L' ' || t[1 + n] == L'\t';
}

static void emit_cmd(const wchar_t *path, const FString *s)
{
    char utf8[1500];
    int wlen = s->Num - 1, n, i;
    if (wlen > 400) wlen = 400;
    n = WideCharToMultiByte(CP_UTF8, 0, s->Data, wlen, utf8, (int)sizeof(utf8) - 2, NULL, NULL);
    if (n <= 0) return;
    for (i = 0; i < n; i++) if (utf8[i] == '\r' || utf8[i] == '\n') utf8[i] = ' ';
    utf8[n++] = '\n';
    append_file(path, utf8, (DWORD)n);
}

static void __fastcall hook_send_chat(void *self, FString *text)
{
    int i;
    for (i = 0; i < NROUTES; i++) {
        if (is_route_cmd(text, g_routes[i].cmd)) { emit_cmd(g_routes[i].path, text); return; }   /* команда мода: на сервер не отправляем */
    }
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

/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * PROBE: поиск структуры хендлинга за указателями.
 * Запрос приходит из Lua-мода VTune (/vtune probe): файл %TEMP%\vtune_probe_req.txt со строками
 *   veh=0x<адрес объекта машины>   sub=0x<адрес HandlingDataSubsystem>
 * Мы читаем память безопасно (ReadProcessMemory на себя), ищем по сигнатуре значений структуру
 * хендлинга: прямо в объекте, за указателем и за указателем второго уровня. Отчёт пишется рядом с exe
 * в vtune_probe.txt. Ничего в игре НЕ изменяется — только чтение.
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */
/* PROBE_CORE_BEGIN */
typedef size_t (*probe_read_fn)(uint64_t addr, void *buf, size_t n);   /* возвращает, сколько байт прочитано */
static probe_read_fn g_pread = NULL;

static char   g_rep[262144];
static size_t g_replen = 0;
static void rep(const char *fmt, ...)
{
    va_list ap;
    int n;
    size_t room;
    if (g_replen + 2 >= sizeof(g_rep)) return;
    room = sizeof(g_rep) - g_replen - 1;
    va_start(ap, fmt);
    n = vsnprintf(g_rep + g_replen, room, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= room) n = (int)room - 1;
    g_replen += (size_t)n;
}

typedef struct { int off; float lo, hi; } PChk;
static const PChk P_CHK[8] = {
    { 0x04, 200.0f, 40000.0f },   /* mass */
    { 0x10, 0.0f, 30.0f },        /* drag */
    { 0x38, 0.05f, 10.0f },       /* traction */
    { 0x58, 0.001f, 5.0f },       /* accel */
    { 0x60, 5.0f, 600.0f },       /* speed */
    { 0x70, 0.05f, 30.0f },       /* brake */
    { 0x74, 0.0f, 1.0f },         /* brakebias */
    { 0x78, 5.0f, 90.0f },        /* steer */
};
#define P_STRUCT_MIN 0x7C
#define P_DETAIL_BYTES 0xB0

static int p_score(const uint8_t *p, int minscore)
{
    int fails = 0, k, maxfail = 8 - minscore;
    for (k = 0; k < 8; k++) {
        float f;
        memcpy(&f, p + P_CHK[k].off, 4);
        if (!(f >= P_CHK[k].lo && f <= P_CHK[k].hi)) { if (++fails > maxfail) return 0; }
    }
    return 8 - fails;
}

#define P_MAXC 160
typedef struct { uint64_t addr; uint64_t blk; int score; char path[128]; } PCand;
static PCand g_pc[P_MAXC];
static int g_npc = 0;
static unsigned long g_pblocks = 0, g_pfail = 0, g_pptrs = 0;

static void p_add(uint64_t addr, uint64_t blk, int score, const char *path)
{
    int i, worst = 0;
    for (i = 0; i < g_npc; i++) if (g_pc[i].addr == addr) return;
    if (g_npc < P_MAXC) {
        i = g_npc++;
    } else {
        for (i = 1; i < g_npc; i++) if (g_pc[i].score < g_pc[worst].score) worst = i;
        if (g_pc[worst].score >= score) return;
        i = worst;
    }
    g_pc[i].addr = addr;
    g_pc[i].blk = blk;
    g_pc[i].score = score;
    snprintf(g_pc[i].path, sizeof(g_pc[i].path), "%s", path);
}

/* просмотреть блок памяти: структура может начинаться с любого 4-байтного смещения */
static void p_scan(uint64_t base, const uint8_t *buf, size_t len, const char *path, int minscore)
{
    size_t off;
    char tmp[128];
    if (len < P_STRUCT_MIN) return;
    g_pblocks++;
    for (off = 0; off + P_STRUCT_MIN <= len; off += 4) {
        int s = p_score(buf + off, minscore);
        if (s >= minscore) {
            snprintf(tmp, sizeof(tmp), "%s+0x%llX", path, (unsigned long long)off);
            p_add(base + off, base, s, tmp);
        }
    }
}

static int p_ptr_ok(uint64_t v) { return v >= 0x10000ULL && v < 0x800000000000ULL && (v & 7) == 0; }

static uint8_t g_root[0x2400], g_b1[0x10100], g_b2[0x4100];

static void p_probe(const char *label, uint64_t root, size_t rootsz, size_t win1, size_t l2words, size_t win2, int minscore)
{
    size_t got, got1, got2, i, j;
    char path[96], path2[128];
    if (rootsz > sizeof(g_root)) rootsz = sizeof(g_root);
    if (win1 > sizeof(g_b1) - 0x100) win1 = sizeof(g_b1) - 0x100;
    if (win2 > sizeof(g_b2) - 0x100) win2 = sizeof(g_b2) - 0x100;
    got = g_pread(root, g_root, rootsz);
    rep("── %s: объект 0x%llX, прочитано 0x%llX из 0x%llX байт ──\n", label, (unsigned long long)root,
        (unsigned long long)got, (unsigned long long)rootsz);
    if (got < 8) { rep("  объект не читается\n"); return; }
    p_scan(root, g_root, got, label, minscore);                       /* уровень 0: прямо в объекте */
    for (i = 0; i + 8 <= got; i += 8) {                                 /* уровень 1: слова-указатели объекта */
        uint64_t p;
        memcpy(&p, g_root + i, 8);
        if (!p_ptr_ok(p)) continue;
        g_pptrs++;
        got1 = g_pread(p, g_b1, win1);
        if (got1 < P_STRUCT_MIN) { g_pfail++; continue; }
        snprintf(path, sizeof(path), "%s+0x%llX->", label, (unsigned long long)i);
        p_scan(p, g_b1, got1, path, minscore);
        for (j = 0; j < l2words && j * 8 + 8 <= got1; j++) {          /* уровень 2: указатели внутри блока */
            uint64_t q;
            memcpy(&q, g_b1 + j * 8, 8);
            if (!p_ptr_ok(q) || q == p) continue;
            got2 = g_pread(q, g_b2, win2);
            if (got2 < P_STRUCT_MIN) continue;
            snprintf(path2, sizeof(path2), "%s+0x%llX->+0x%llX->", label, (unsigned long long)i, (unsigned long long)(j * 8));
            p_scan(q, g_b2, got2, path2, minscore);
        }
    }
}

static void p_report(void)
{
    int i, j, n;
    uint8_t buf[P_DETAIL_BYTES];
    for (i = 1; i < g_npc; i++) {                                       /* сортировка по убыванию баллов */
        PCand t = g_pc[i];
        for (j = i - 1; j >= 0 && g_pc[j].score < t.score; j--) g_pc[j + 1] = g_pc[j];
        g_pc[j + 1] = t;
    }
    rep("\nпросмотрено блоков: %lu, указателей: %lu, нечитаемых: %lu\n", g_pblocks, g_pptrs, g_pfail);
    rep("кандидатов: %d (баллов из 8; настоящая структура даёт 8 и повторяется при каждом запуске)\n", g_npc);
    n = g_npc < 30 ? g_npc : 30;
    for (i = 0; i < n; i++) rep("  %d/8  0x%llX  %s\n", g_pc[i].score, (unsigned long long)g_pc[i].addr, g_pc[i].path);
    n = g_npc < 6 ? g_npc : 6;
    for (i = 0; i < n; i++) {
        size_t got = g_pread(g_pc[i].addr, buf, sizeof(buf));
        size_t w;
        rep("\n[%d] %d/8  0x%llX  %s  (слова: смещение, hex, float)\n", i + 1, g_pc[i].score,
            (unsigned long long)g_pc[i].addr, g_pc[i].path);
        for (w = 0; w + 4 <= got; w += 4) {
            uint32_t u;
            float f;
            memcpy(&u, buf + w, 4);
            memcpy(&f, buf + w, 4);
            rep("  +0x%02X  %08X  %g\n", (unsigned)w, (unsigned)u, (double)f);
        }
    }
}


/* таблица записей для сопоставления с машиной */
typedef struct { uint64_t addr; uint32_t id; uint32_t v[7]; } PEnt;   /* v: mass turnmass accel inertia speed brake traction */
#define P_MAXENT 2048
static PEnt g_ent[P_MAXENT];
static int g_nent = 0;
static void p_ent_add(uint64_t addr, const uint8_t *e)
{
    int i;
    PEnt *t;
    uint32_t id0;
    if (g_nent >= P_MAXENT) return;
    memcpy(&id0, e, 4);
    if ((addr & 0xF) != 0 || id0 > 100000u) return;   /* мусор: настоящие записи лежат по адресу кратному 16 (MakeShared 0xC0 + 0x10), id маленький */
    for (i = 0; i < g_nent; i++) if (g_ent[i].addr == addr) return;
    t = &g_ent[g_nent++];
    t->addr = addr;
    memcpy(&t->id, e, 4);
    memcpy(&t->v[0], e + 0x04, 4); memcpy(&t->v[1], e + 0x0C, 4); memcpy(&t->v[2], e + 0x58, 4);
    memcpy(&t->v[3], e + 0x5C, 4); memcpy(&t->v[4], e + 0x60, 4); memcpy(&t->v[5], e + 0x70, 4);
    memcpy(&t->v[6], e + 0x38, 4);
}

/* полный обход таблицы: для каждого блока с кандидатами идём шагом 0xC0 от найденной записи вверх и вниз */
#define P_STRIDE 0xC0
static uint8_t g_big[0x40100];
#define PREP if (print) rep
static void p_enum(int print)
{
    uint64_t blks[32]; unsigned phs[32];
    int nb = 0, i, b;
    for (i = 0; i < g_npc && nb < 32; i++) {
        unsigned ph;
        int dup = 0;
        if (g_pc[i].score < 6) continue;
        ph = (unsigned)((g_pc[i].addr - g_pc[i].blk) % P_STRIDE);
        for (b = 0; b < nb; b++) if (blks[b] == g_pc[i].blk && phs[b] == ph) dup = 1;
        if (!dup) { blks[nb] = g_pc[i].blk; phs[nb] = ph; nb++; }
    }
    PREP("\n══ ТАБЛИЦА хендлингов: блоков %d, шаг записи 0x%X ══\n", nb, P_STRIDE);
    PREP("колонки: адрес записи | w0 | mass turnmass drag traction accel inertia speed brake brakebias steer | gears flags | слова +0xB0..+0xBC\n");
    for (b = 0; b < nb; b++) {
        size_t got = g_pread(blks[b], g_big, 0x40000), off;
        int cnt = 0;
        PREP("\nблок 0x%llX фаза 0x%X (прочитано 0x%llX)\n", (unsigned long long)blks[b], phs[b], (unsigned long long)got);
        for (off = phs[b]; off + P_STRIDE <= got; off += P_STRIDE) {
            const uint8_t *e = g_big + off;
            float mass, trac, spd, turn, drag, acc, inr, brk, bias, str;
            uint32_t w0, fl, n0, n1, n2, n3;
            memcpy(&mass, e + 0x04, 4); memcpy(&trac, e + 0x38, 4); memcpy(&spd, e + 0x60, 4);
            if (!(mass >= 100.0f && mass <= 200000.0f && spd >= 1.0f && spd <= 1000.0f && trac >= 0.01f && trac <= 50.0f)) continue;
            if (cnt >= 400) break;
            cnt++;
            p_ent_add(blks[b] + off, e);
            memcpy(&w0, e, 4); memcpy(&turn, e + 0x0C, 4); memcpy(&drag, e + 0x10, 4); memcpy(&acc, e + 0x58, 4);
            memcpy(&inr, e + 0x5C, 4); memcpy(&brk, e + 0x70, 4); memcpy(&bias, e + 0x74, 4); memcpy(&str, e + 0x78, 4);
            memcpy(&fl, e + 0xA8, 4); memcpy(&n0, e + 0xB0, 4); memcpy(&n1, e + 0xB4, 4); memcpy(&n2, e + 0xB8, 4); memcpy(&n3, e + 0xBC, 4);
            PREP("0x%llX | %u | %g %g %g %g %g %g %g %g %g %g | %u %08X | %08X %08X %08X %08X\n",
                (unsigned long long)(blks[b] + off), (unsigned)w0, (double)mass, (double)turn, (double)drag, (double)trac,
                (double)acc, (double)inr, (double)spd, (double)brk, (double)bias, (double)str,
                (unsigned)e[0x52], (unsigned)fl, (unsigned)n0, (unsigned)n1, (unsigned)n2, (unsigned)n3);
        }
        PREP("  записей в блоке: %d\n", cnt);
    }
}

#undef PREP
/* ── сопоставление: чьи значения (масса, ускорение, скорость…) лежат в памяти самой машины ── */
#define HS_BITS 20
#define HS_SIZE (1u << HS_BITS)
static uint32_t g_hs[HS_SIZE];
static unsigned long g_hs_n = 0;
static void hs_add(uint32_t v)
{
    uint32_t h;
    if (!v || g_hs_n > 700000UL) return;
    h = (v * 2654435761u) >> (32 - HS_BITS);
    for (;; h = (h + 1) & (HS_SIZE - 1)) {
        if (g_hs[h] == v) return;
        if (!g_hs[h]) { g_hs[h] = v; g_hs_n++; return; }
    }
}
static int hs_has(uint32_t v)
{
    uint32_t h;
    if (!v) return 0;
    h = (v * 2654435761u) >> (32 - HS_BITS);
    for (;; h = (h + 1) & (HS_SIZE - 1)) {
        if (g_hs[h] == v) return 1;
        if (!g_hs[h]) return 0;
    }
}
static void p_collect(uint64_t root, size_t rootsz, size_t win1)
{
    size_t got, i, k, g1;
    if (rootsz > sizeof(g_root)) rootsz = sizeof(g_root);
    if (win1 > sizeof(g_b1) - 0x100) win1 = sizeof(g_b1) - 0x100;
    got = g_pread(root, g_root, rootsz);
    for (i = 0; i + 4 <= got; i += 4) { uint32_t w; memcpy(&w, g_root + i, 4); hs_add(w); }
    for (i = 0; i + 8 <= got; i += 8) {
        uint64_t p;
        memcpy(&p, g_root + i, 8);
        if (!p_ptr_ok(p)) continue;
        g1 = g_pread(p, g_b1, win1);
        for (k = 0; k + 4 <= g1; k += 4) { uint32_t w; memcpy(&w, g_b1 + k, 4); hs_add(w); }
    }
}
static void p_vehmatch(uint64_t veh, uint64_t cfg)
{
    int i, j, best[10], nb = 0;
    int sc[P_MAXENT];
    memset(g_hs, 0, sizeof(g_hs));
    g_hs_n = 0;
    if (veh) p_collect(veh, 0x2000, 0x800);
    if (cfg) p_collect(cfg, 0x400, 0x400);
    rep("\n══ СОВПАДЕНИЯ: записи таблицы, чьи значения есть в памяти машины (слов в наборе: %lu, записей: %d) ══\n", g_hs_n, g_nent);
    for (i = 0; i < g_nent; i++) {
        int c = 0;
        for (j = 0; j < 7; j++) if (hs_has(g_ent[i].v[j])) c++;
        sc[i] = c;
    }
    for (i = 0; i < g_nent; i++) {                 /* топ-10 по числу совпадений (из 7) */
        int pos = nb;
        if (sc[i] < 2) continue;
        if (nb < 10) nb++; else if (sc[best[9]] >= sc[i]) continue; else pos = 9;
        while (pos > 0 && sc[best[pos - 1]] < sc[i]) { if (pos < 10) best[pos] = best[pos - 1]; pos--; }
        best[pos] = i;
    }
    if (nb == 0) rep("совпадений (>=2 из 7) нет: машина не хранит копию значений хендлинга\n");
    for (i = 0; i < nb; i++) {
        PEnt *t = &g_ent[best[i]];
        float f[7];
        memcpy(f, t->v, sizeof(f));
        rep("  %d/7  id=%u  адрес записи 0x%llX  mass=%g turn=%g accel=%g inertia=%g speed=%g brake=%g trac=%g\n",
            sc[best[i]], (unsigned)t->id, (unsigned long long)t->addr,
            (double)f[0], (double)f[1], (double)f[2], (double)f[3], (double)f[4], (double)f[5], (double)f[6]);
    }
}
/* PROBE_CORE_END */

/* ── Windows-часть: чтение памяти, запрос, отчёт ── */
static size_t win_read(uint64_t addr, void *buf, size_t n)
{
    size_t done = 0;
    HANDLE self = GetCurrentProcess();
    while (done < n) {
        uint64_t cur = addr + done;
        size_t pageleft = 0x1000 - (size_t)(cur & 0xFFF);
        size_t c = (n - done < pageleft) ? (n - done) : pageleft;
        SIZE_T got = 0;
        if (!ReadProcessMemory(self, (LPCVOID)(uintptr_t)cur, (uint8_t *)buf + done, c, &got) || got != c) break;
        done += c;
    }
    return done;
}

static void probe_write_report(void)
{
    wchar_t path[MAX_PATH + 32];
    size_t len;
    HANDLE h;
    DWORD w = 0;
    len = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return;
    while (len > 0 && path[len - 1] != L'\\' && path[len - 1] != L'/') len--;
    path[len] = 0;
    wcscat(path, L"vtune_probe.txt");
    h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { hook_log("probe: не удалось создать vtune_probe.txt (%lu)", GetLastError()); return; }
    WriteFile(h, g_rep, (DWORD)g_replen, &w, NULL);
    CloseHandle(h);
    hook_log("probe: отчёт vtune_probe.txt записан (%lu байт), кандидатов: %d", (unsigned long)w, g_npc);
}

static void run_probe(uint64_t veh, uint64_t sub, uint64_t cfg)
{
    g_pread = win_read;
    g_replen = 0; g_nent = 0; g_npc = 0; g_pblocks = 0; g_pfail = 0; g_pptrs = 0;
    rep("VTune probe (version.dll): veh=0x%llX sub=0x%llX cfg=0x%llX\n", (unsigned long long)veh, (unsigned long long)sub, (unsigned long long)cfg);
    __try {
        if (veh) p_probe("veh", veh, 0x2000, 0x800, 64, 0x400, 6);
        if (sub) p_probe("sub", sub, 0x400, 0x10000, 64, 0x4000, 6);
        p_report();
        p_enum(0);                  /* тихий проход: собрать записи */
        p_vehmatch(veh, cfg);       /* сопоставление идёт первым — чтобы не потерялось при обрезке отчёта */
        p_enum(1);                  /* полный список записей */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rep("\nИСКЛЮЧЕНИЕ внутри probe — отчёт неполный\n");
    }
    probe_write_report();
}

static unsigned long long parse_hex_key(const char *buf, const char *key)
{
    const char *p = strstr(buf, key);
    if (!p) return 0;
    return strtoull(p + strlen(key), NULL, 16);
}


/* ══════════════════════════════════════════════════════════════════════════════════════════════
 * TBL: прямая правка таблицы хендлингов в памяти игры (команда /vtune tbl …).
 * Запрос от Lua-мода: файл %TEMP%\vtune_tbl_req.txt, первая строка «sub=0x<адрес HandlingDataSubsystem>»,
 * дальше команды (по одной в строке):
 *   list                      записать ВСЕ записи таблицы в vtune_tbl.txt рядом с exe (id, счётчик ссылок, поля)
 *   get <id>                  показать поля записи
 *   set <id|a-b|all> <поле> <значение|xМножитель>    записать поле (speed, accel, mass, grip…)
 *   reset                     вернуть всё, что меняли
 *   refresh                   заново найти таблицу
 * Ответы — строки «tbl: …» в airbreak_hook.log (мод VTune печатает их в UE4SS.log).
 * Пишутся только float-поля записей таблицы; ничего больше в игре не трогается.
 * ══════════════════════════════════════════════════════════════════════════════════════════════ */
typedef struct { const char *name; uint32_t off; } TblField;
static const TblField TBL_F[] = {
    { "mass", 0x04 }, { "turnmass", 0x0C }, { "drag", 0x10 }, { "traction", 0x38 }, { "grip", 0x38 },
    { "accel", 0x58 }, { "inertia", 0x5C }, { "speed", 0x60 }, { "brake", 0x70 }, { "brakebias", 0x74 },
    { "steer", 0x78 }, { "tloss", 0x7C }, { "tbias", 0x80 }, { "force", 0x84 }, { "damp", 0x88 },
    { "hsdamp", 0x8C }, { "upper", 0x90 }, { "lower", 0x94 }, { "fr", 0x98 }, { "antidive", 0x9C },
    { "seat", 0xA0 }, { "crash", 0xA4 },
};
#define TBL_NF ((int)(sizeof(TBL_F) / sizeof(TBL_F[0])))
typedef struct { uint64_t addr; uint32_t old; } TblUndo;
#define TBL_MAXUNDO 16384
static TblUndo g_undo[TBL_MAXUNDO];
static int g_nundo = 0;
static uint64_t g_tbl_sub = 0;

static const TblField *tbl_field(const char *s)
{
    int i;
    for (i = 0; i < TBL_NF; i++) if (_stricmp(s, TBL_F[i].name) == 0) return &TBL_F[i];
    return NULL;
}

static int tbl_refresh(uint64_t sub)
{
    g_pread = win_read;
    g_replen = 0; g_nent = 0; g_npc = 0; g_pblocks = 0; g_pfail = 0; g_pptrs = 0;
    __try {
        p_probe("sub", sub, 0x400, 0x10000, 64, 0x4000, 6);
        p_enum(0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hook_log("tbl: исключение при поиске таблицы");
    }
    g_tbl_sub = sub;
    hook_log("tbl: таблица хендлингов: записей %d (подсистема 0x%llX)", g_nent, (unsigned long long)sub);
    return g_nent;
}

static void tbl_write_file(const wchar_t *name, const char *buf, size_t len)
{
    wchar_t path[MAX_PATH + 32];
    size_t n;
    HANDLE h;
    DWORD w = 0;
    n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    while (n > 0 && path[n - 1] != L'\\' && path[n - 1] != L'/') n--;
    path[n] = 0;
    wcscat(path, name);
    h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { hook_log("tbl: не удалось создать файл (%lu)", GetLastError()); return; }
    WriteFile(h, buf, (DWORD)len, &w, NULL);
    CloseHandle(h);
}

static float tbl_getf(uint64_t addr, uint32_t off, int *ok)
{
    float f = 0.0f;
    *ok = (g_pread(addr + off, &f, 4) == 4);
    return f;
}

static void tbl_list(void)
{
    static char buf[400000];
    size_t len = 0;
    int i;
    len += (size_t)snprintf(buf + len, sizeof(buf) - len,
        "VTune tbl list: записей %d. Колонки: id | адрес записи | refs(счётчик shared-ссылок) | mass turnmass drag traction accel inertia speed brake steer\n", g_nent);
    for (i = 0; i < g_nent && len + 300 < sizeof(buf); i++) {
        PEnt *t = &g_ent[i];
        uint32_t refs = 0;
        int ok;
        float m, tm, dr, tr, ac, in, sp, br, st;
        g_pread(t->addr - 8, &refs, 4);
        m = tbl_getf(t->addr, 0x04, &ok);  tm = tbl_getf(t->addr, 0x0C, &ok); dr = tbl_getf(t->addr, 0x10, &ok);
        tr = tbl_getf(t->addr, 0x38, &ok); ac = tbl_getf(t->addr, 0x58, &ok); in = tbl_getf(t->addr, 0x5C, &ok);
        sp = tbl_getf(t->addr, 0x60, &ok); br = tbl_getf(t->addr, 0x70, &ok); st = tbl_getf(t->addr, 0x78, &ok);
        len += (size_t)snprintf(buf + len, sizeof(buf) - len, "%u | 0x%llX | %u | %g %g %g %g %g %g %g %g %g\n",
            (unsigned)t->id, (unsigned long long)t->addr, (unsigned)refs,
            (double)m, (double)tm, (double)dr, (double)tr, (double)ac, (double)in, (double)sp, (double)br, (double)st);
    }
    tbl_write_file(L"vtune_tbl.txt", buf, len);
    hook_log("tbl: список записан в vtune_tbl.txt рядом с exe (%d записей)", g_nent);
}

static void tbl_get(uint32_t id)
{
    int i, n = 0, k;
    for (i = 0; i < g_nent; i++) {
        PEnt *t = &g_ent[i];
        char line[500];
        size_t len = 0;
        if (t->id != id) continue;
        n++;
        len += (size_t)snprintf(line + len, sizeof(line) - len, "tbl: id %u @0x%llX:", (unsigned)id, (unsigned long long)t->addr);
        for (k = 0; k < TBL_NF; k++) {
            int ok;
            float f;
            if (k > 0 && TBL_F[k].off == TBL_F[k - 1].off) continue;   /* алиас grip */
            f = tbl_getf(t->addr, TBL_F[k].off, &ok);
            if (ok) len += (size_t)snprintf(line + len, sizeof(line) - len, " %s=%g", TBL_F[k].name, (double)f);
        }
        hook_log("%s", line);
    }
    if (!n) hook_log("tbl: записи с id %u нет", (unsigned)id);
}

/* who: «all», «N» или «A-B» */
static int tbl_orig(uint64_t a, uint32_t *old)
{
    int k;
    for (k = 0; k < g_nundo; k++) if (g_undo[k].addr == a) { *old = g_undo[k].old; return 1; }
    return 0;
}
static void tbl_set(const char *who, const TblField *f, float val, int mul)
{
    unsigned long lo = 0, hi = 0xFFFFFFFFUL;
    int i, changed = 0, bad = 0;
    float first_old = 0.0f, first_new = 0.0f;
    if (_stricmp(who, "all") != 0) {
        char *end = NULL;
        lo = strtoul(who, &end, 10);
        hi = lo;
        if (end && *end == '-') hi = strtoul(end + 1, NULL, 10);
    }
    for (i = 0; i < g_nent; i++) {
        PEnt *t = &g_ent[i];
        uint32_t w;
        float cur, nv;
        uint64_t a;
        SIZE_T wr = 0;
        if (t->id < lo || t->id > hi) continue;
        a = t->addr + f->off;
        if (g_pread(a, &w, 4) != 4) { bad++; continue; }
        memcpy(&cur, &w, 4);
        { uint32_t ow; float of = cur; if (tbl_orig(a, &ow)) memcpy(&of, &ow, 4); nv = mul ? of * val : val; }
        if (!(nv == nv) || nv > 1e7f || nv < -1e7f) { bad++; continue; }
        if (g_nundo >= TBL_MAXUNDO) { hook_log("tbl: слишком много правок — сделайте «reset»"); break; }
        if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)a, &nv, 4, &wr) || wr != 4) { bad++; continue; }
        { uint32_t ow; if (!tbl_orig(a, &ow)) { g_undo[g_nundo].addr = a; g_undo[g_nundo].old = w; g_nundo++; } }
        if (!changed) { first_old = cur; first_new = nv; }
        changed++;
    }
    if (changed) hook_log("tbl: %s -> %s: записей изменено %d (первая: %g -> %g)%s", who, f->name, changed,
                          (double)first_old, (double)first_new, bad ? ", с ошибками" : "");
    else hook_log("tbl: ничего не изменено (нет записей для «%s» или запись не читается/не пишется, ошибок: %d)", who, bad);
}

static void tbl_reset(void)
{
    int i, n = 0;
    for (i = g_nundo - 1; i >= 0; i--) {
        SIZE_T wr = 0;
        if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)g_undo[i].addr, &g_undo[i].old, 4, &wr) && wr == 4) n++;
    }
    hook_log("tbl: возвращено значений: %d из %d", n, g_nundo);
    g_nundo = 0;
}

static void tbl_exec(char *line)
{
    char *tok[6];
    int n = 0;
    char *p = line, *e;
    while (*p && n < 6) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    if (n == 0) return;
    if (_stricmp(tok[0], "list") == 0) tbl_list();
    else if (_stricmp(tok[0], "get") == 0 && n >= 2) tbl_get((uint32_t)strtoul(tok[1], NULL, 10));
    else if (_stricmp(tok[0], "reset") == 0) tbl_reset();
    else if (_stricmp(tok[0], "set") == 0 && n >= 4) {
        const TblField *f = tbl_field(tok[2]);
        int mul = 0;
        char *v = tok[3];
        float val;
        if (!f) { hook_log("tbl: нет поля «%s»", tok[2]); return; }
        if (*v == 'x' || *v == 'X' || *v == '*') { mul = 1; v++; }
        for (e = v; *e; e++) if (*e == ',') *e = '.';
        val = (float)strtod(v, &e);
        if (e == v) { hook_log("tbl: значение «%s» не число", tok[3]); return; }
        tbl_set(tok[1], f, val, mul);
    }
    else hook_log("tbl: неизвестная команда «%s» (list | get <id> | set <id|a-b|all> <поле> <знач|xN> | reset | refresh)", tok[0]);
}

static void tbl_poll(void)
{
    wchar_t req[MAX_PATH + 32];
    HANDLE h;
    char buf[2048];
    DWORD got = 0;
    char *line, *next;
    uint64_t sub = 0;
    int force = 0, refreshed = 0;
    temp_path(L"vtune_tbl_req.txt", req, sizeof(req) / sizeof(req[0]));
    if (GetFileAttributesW(req) == INVALID_FILE_ATTRIBUTES) return;
    h = CreateFileW(req, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
    CloseHandle(h);
    buf[got] = 0;
    if (got < 8 || buf[got - 1] != '\n') return;        /* файл ещё дописывается */
    DeleteFileW(req);
    for (line = buf; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        { char *cr = strchr(line, '\r'); if (cr) *cr = 0; }
        if (strncmp(line, "sub=", 4) == 0) { sub = strtoull(line + 4, NULL, 16); continue; }
        if (_stricmp(line, "refresh") == 0) { force = 1; continue; }
        if (!line[0]) continue;
        if (!refreshed && (g_nent == 0 || force || sub)) {
            if (!sub) { hook_log("tbl: нет адреса подсистемы"); return; }
            if (tbl_refresh(sub) == 0) { hook_log("tbl: таблица не найдена"); return; }
            force = 0; refreshed = 1;
        }
        __try { tbl_exec(line); }
        __except (EXCEPTION_EXECUTE_HANDLER) { hook_log("tbl: исключение при выполнении команды"); }
    }
    if (force && sub) tbl_refresh(sub);
}

static DWORD WINAPI probe_thread(LPVOID unused)
{
    wchar_t req[MAX_PATH + 32];
    (void)unused;
    temp_path(L"vtune_probe_req.txt", req, sizeof(req) / sizeof(req[0]));
    DeleteFileW(req);
    for (;;) {
        HANDLE h;
        char buf[256];
        DWORD got = 0;
        Sleep(300);
        tbl_poll();                            /* /vtune tbl … */
        if (GetFileAttributesW(req) == INVALID_FILE_ATTRIBUTES) continue;
        h = CreateFileW(req, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        ReadFile(h, buf, sizeof(buf) - 1, &got, NULL);
        CloseHandle(h);
        buf[got] = 0;
        if (got < 6) continue;                 /* файл ещё дописывается — подождём следующего тика */
        DeleteFileW(req);
        hook_log("probe: запрос получен: %s", buf);
        run_probe(parse_hex_key(buf, "veh="), parse_hex_key(buf, "sub="), parse_hex_key(buf, "cfg="));
    }
    return 0;
}

static DWORD WINAPI install_thread(LPVOID unused)
{
    int i, r = 0;
    wchar_t logp[MAX_PATH + 32];
    (void)unused;
    for (i = 0; i < NROUTES; i++) {
        temp_path(g_routes[i].file, g_routes[i].path, sizeof(g_routes[i].path) / sizeof(g_routes[i].path[0]));
        DeleteFileW(g_routes[i].path);     /* старые команды от прошлого запуска не нужны */
    }
    temp_path(L"airbreak_hook.log", logp, sizeof(logp) / sizeof(logp[0]));
    DeleteFileW(logp);
    hook_log("version.dll (AirBreak) загружена, ищу SendChatInput (команды: /air, /vtune)");
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
            t = CreateThread(NULL, 0, probe_thread, NULL, 0, NULL);     /* /vtune probe: поиск структуры хендлинга */
            if (t) CloseHandle(t);
        }
    }
    return TRUE;
}
