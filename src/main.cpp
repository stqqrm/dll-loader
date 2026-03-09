#include "dll/dll.h"
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <tlhelp32.h>
#include <psapi.h>

#undef min
#undef max

namespace fs = std::filesystem;

inline void relaunch_as_admin()
{
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOASYNC;

    if (ShellExecuteExW(&sei))
        ExitProcess(0);
}

static fs::path get_persist_path()
{
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    return fs::path(tmp) / L"dll_injector_last.txt";
}

static void save_dll_path(const fs::path& dll)
{
    HANDLE h = CreateFileW(
        get_persist_path().c_str(),
        GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::wstring s = dll.wstring();
    DWORD        written = 0;
    WriteFile(h, s.c_str(), (DWORD)(s.size() * sizeof(wchar_t)), &written, nullptr);
    CloseHandle(h);
}

static fs::path load_dll_path()
{
    HANDLE h = CreateFileW(
        get_persist_path().c_str(),
        GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};

    DWORD size = GetFileSize(h, nullptr);
    if (size == 0 || size == INVALID_FILE_SIZE) { CloseHandle(h); return {}; }

    std::wstring s(size / sizeof(wchar_t), L'\0');
    DWORD        read = 0;
    ReadFile(h, s.data(), size, &read, nullptr);
    CloseHandle(h);

    fs::path p(s);
    return fs::exists(p) ? p : fs::path{};
}

struct Cell {
    wchar_t ch = L' ';
    WORD    attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
};

struct Surface {
    int w = 0, h = 0;
    std::vector<Cell> buf;
    HANDLE hout = INVALID_HANDLE_VALUE;

    void init() {
        hout = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO ci;
        GetConsoleScreenBufferInfo(hout, &ci);
        w = ci.srWindow.Right - ci.srWindow.Left + 1;
        h = ci.srWindow.Bottom - ci.srWindow.Top + 1;
        buf.assign(w * h, Cell{});
        CONSOLE_CURSOR_INFO cci{ 1, FALSE };
        SetConsoleCursorInfo(hout, &cci);
    }

    void clear(WORD attr = 0) {
        for (auto& c : buf) { c.ch = L' '; c.attr = attr; }
    }

    void put(int x, int y, wchar_t ch, WORD attr) {
        if (x < 0 || x >= w || y < 0 || y >= h) return;
        buf[y * w + x] = { ch, attr };
    }

    void text(int x, int y, const wchar_t* s, WORD attr) {
        for (int i = 0; s[i]; ++i) put(x + i, y, s[i], attr);
    }

    void hline(int x, int y, int len, wchar_t ch, WORD attr) {
        for (int i = 0; i < len; ++i) put(x + i, y, ch, attr);
    }

    void rect(int x, int y, int rw, int rh, WORD attr) {
        put(x, y, L'+', attr);
        put(x + rw - 1, y, L'+', attr);
        put(x, y + rh - 1, L'+', attr);
        put(x + rw - 1, y + rh - 1, L'+', attr);
        for (int i = 1; i < rw - 1; ++i) {
            put(x + i, y, L'-', attr);
            put(x + i, y + rh - 1, L'-', attr);
        }
        for (int i = 1; i < rh - 1; ++i) {
            put(x, y + i, L'|', attr);
            put(x + rw - 1, y + i, L'|', attr);
        }
    }

    std::wstring fit(const std::wstring& s, int width) {
        if (width <= 0) return L"";
        if ((int)s.size() >= width) return s.substr(0, width);
        return s + std::wstring(width - s.size(), L' ');
    }

    void flush() {
        std::vector<CHAR_INFO> ci(w * h);
        for (int i = 0; i < w * h; ++i) {
            ci[i].Char.UnicodeChar = buf[i].ch;
            ci[i].Attributes = buf[i].attr;
        }
        COORD      size = { (SHORT)w, (SHORT)h };
        COORD      origin = { 0, 0 };
        SMALL_RECT region = { 0, 0, (SHORT)(w - 1), (SHORT)(h - 1) };
        WriteConsoleOutputW(hout, ci.data(), size, origin, &region);
    }
};

struct ProcEntry {
    DWORD        pid = 0;
    std::wstring name;
    std::wstring window;
    bool         hasWindow = false;
};

struct EnumData {
    std::vector<std::pair<DWORD, std::wstring>>* visible;
};

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lp) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    wchar_t title[256] = {};
    if (!GetWindowTextW(hwnd, title, 256) || !title[0]) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    reinterpret_cast<EnumData*>(lp)->visible->push_back({ pid, title });
    return TRUE;
}

static std::vector<ProcEntry> enumerate_processes() {
    std::vector<std::pair<DWORD, std::wstring>> visWindows;
    EnumData ed{ &visWindows };
    EnumWindows(EnumWindowsProc, (LPARAM)&ed);

    std::unordered_map<DWORD, std::wstring> winMap;
    for (auto& [pid, title] : visWindows)
        winMap.emplace(pid, title);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    std::vector<ProcEntry> procs;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcEntry entry;
            entry.pid = pe.th32ProcessID;
            entry.name = pe.szExeFile;
            auto it = winMap.find(entry.pid);
            if (it != winMap.end()) {
                entry.hasWindow = true;
                entry.window = it->second;
            }
            procs.push_back(entry);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::stable_sort(procs.begin(), procs.end(), [](const ProcEntry& a, const ProcEntry& b) {
        if (a.hasWindow != b.hasWindow) return a.hasWindow > b.hasWindow;
        return a.name < b.name;
        });

    return procs;
}

inline bool get_module_info(HANDLE hproc, fs::path dll_path, LPMODULEINFO mi)
{
    HMODULE mods[1024];
    DWORD   needed = 0;
    if (!EnumProcessModules(hproc, mods, sizeof(mods), &needed))
        return false;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        wchar_t name[MAX_PATH] = {};
        if (!GetModuleFileNameExW(hproc, mods[i], name, MAX_PATH))
            continue;
        if (fs::path(name) == dll_path)
            return GetModuleInformation(hproc, mods[i], mi, sizeof(MODULEINFO));
    }
    return false;
}

inline bool does_module_exist(HANDLE proc, HMODULE mod)
{
    HMODULE mods[1024];
    DWORD   needed = 0;
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed))
        return false;
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i)
        if (mods[i] == mod) return true;
    return false;
}

fs::path SelectFile(
    HWND    owner = nullptr,
    LPCWSTR filter = L"DLL Files\0*.dll\0All Files\0*.*\0",
    LPCWSTR title = L"Select DLL",
    LPCWSTR initialDir = nullptr)
{
    wchar_t szFile[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = filter;
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = title;
    ofn.lpstrInitialDir = initialDir;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn))
        return fs::path(szFile);

    DWORD err = CommDlgExtendedError();
    if (err != 0)
        throw std::runtime_error("GetOpenFileName failed: " + std::to_string(err));

    return {};
}

#define C_BORDER   (FOREGROUND_BLUE  | FOREGROUND_INTENSITY)
#define C_HEADER   (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_NORMAL   (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define C_DIM      (FOREGROUND_BLUE  | FOREGROUND_GREEN)
#define C_HOVER    (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | \
                    BACKGROUND_BLUE  | BACKGROUND_INTENSITY)
#define C_MARKED   (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | \
                    BACKGROUND_RED   | BACKGROUND_INTENSITY)
#define C_WINDOW   (FOREGROUND_GREEN | FOREGROUND_BLUE  | FOREGROUND_INTENSITY)
#define C_PID      (FOREGROUND_RED   | FOREGROUND_GREEN)
#define C_STATUS_K (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_STATUS_V (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_ERR      (FOREGROUND_RED   | FOREGROUND_INTENSITY)
#define C_OK       (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_INJECT   (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_MARK_BOX (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_WARN     (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_INTENSITY | \
                    BACKGROUND_RED)
#define C_SEARCH   (FOREGROUND_RED   | FOREGROUND_GREEN | FOREGROUND_BLUE | \
                    BACKGROUND_GREEN | BACKGROUND_INTENSITY)
#define C_SEARCH_K (FOREGROUND_GREEN | FOREGROUND_INTENSITY)

static std::wstring to_lower(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

static bool proc_matches(const ProcEntry& p, const std::wstring& needle_lc) {
    if (needle_lc.empty()) return true;
    if (to_lower(p.name).find(needle_lc) != std::wstring::npos) return true;
    if (p.hasWindow && to_lower(p.window).find(needle_lc) != std::wstring::npos) return true;

    if (to_lower(std::to_wstring(p.pid)).find(needle_lc) != std::wstring::npos) return true;

    return false;
}

struct App {
    Surface                surf;
    std::vector<ProcEntry> procs;
    std::vector<int>       view;
    int                    cursor = 0;
    int                    scroll = 0;
    int                    marked = -1;
    fs::path               dllPath;
    std::wstring           status;
    WORD                   statusColor = C_NORMAL;
    bool                   isAdmin = false;

    bool         searching = false;
    std::wstring searchBuf;

    void set_status(const std::wstring& s, WORD col = C_NORMAL) {
        status = s;
        statusColor = col;
    }

    void rebuild_view() {
        std::wstring needle = to_lower(searchBuf);
        DWORD old_pid = view_cursor_pid();

        view.clear();
        for (int i = 0; i < (int)procs.size(); ++i)
            if (proc_matches(procs[i], needle))
                view.push_back(i);

        cursor = 0;
        if (old_pid) {
            for (int i = 0; i < (int)view.size(); ++i) {
                if (procs[view[i]].pid == old_pid) { cursor = i; break; }
            }
        }
        int lh = list_height();
        if (scroll > cursor) scroll = cursor;
        if (scroll < cursor - lh + 1) scroll = cursor - lh + 1;
        if (scroll < 0) scroll = 0;
    }

    DWORD view_cursor_pid() const {
        if (cursor >= 0 && cursor < (int)view.size())
            return procs[view[cursor]].pid;
        return 0;
    }

    void refresh_procs() {
        DWORD cursorPid = view_cursor_pid();
        DWORD markedPid = (marked >= 0 && marked < (int)procs.size())
            ? procs[marked].pid : 0;

        procs = enumerate_processes();

        marked = -1;
        for (int i = 0; i < (int)procs.size(); ++i)
            if (procs[i].pid == markedPid) { marked = i; break; }

        rebuild_view();

        if (cursorPid) {
            for (int i = 0; i < (int)view.size(); ++i) {
                if (procs[view[i]].pid == cursorPid) { cursor = i; break; }
            }
        }
    }

    int list_top() const { return 3; }

    int hint_rows(int W) const {
        struct Token { const wchar_t* key; const wchar_t* val; };
        Token tokens[] = {
            {L"[Up/Dn]",   L"move"},
            {L"[PgUp/Dn]", L"page"},
            {L"[Rt]",      L"mark"},
            {L"[Lt]",      L"unmark"},
            {L"[I]",       L"inject"},
            {L"[E]",       L"eject"},
            {L"[D]",       L"set dll"},
            {L"[/]",       L"search"},
            {L"[Q]",       L"quit"},
            {L"[R]",       L"Run as Admin"},
        };
        int usable = W - 3;
        int rows = 1, x = 2;
        int count = isAdmin ? 9 : 10;
        for (int i = 0; i < count; ++i) {
            int w = (int)(wcslen(tokens[i].key) + wcslen(tokens[i].val)) + 1;
            if (x + w > usable && x > 2) { ++rows; x = 2; }
            x += w;
        }
        return rows;
    }

    int status_rows(int W) const {
        if (status.empty()) return 0;
        int usable = W - 4;
        if (usable <= 0) return 1;
        return ((int)status.size() + usable - 1) / usable;
    }

    int list_bottom() const { return surf.h - 1 - status_rows(surf.w) - hint_rows(surf.w) - 1; }
    int list_height() const { return list_bottom() - list_top(); }

    void clamp_scroll() {
        int lh = list_height();
        if (cursor < scroll) scroll = cursor;
        if (cursor >= scroll + lh) scroll = cursor - lh + 1;
        if (scroll < 0) scroll = 0;
    }

    void draw() {
        surf.clear(0);

        int W = surf.w;
        int H = surf.h;

        surf.rect(0, 0, W, H, C_BORDER);

        if (!isAdmin) {
            const wchar_t* warn = L" ! NOT ADMINISTRATOR ! ";
            int wx = (W - (int)wcslen(warn)) / 2;
            surf.text(wx, 0, warn, C_WARN);
        }
        else {
            const wchar_t* title = L" DLL Injector ";
            surf.text((W - (int)wcslen(title)) / 2, 0, title, C_HEADER);
        }

        surf.hline(1, 2, W - 2, L'-', C_BORDER);
        surf.put(0, 2, L'+', C_BORDER);
        surf.put(W - 1, 2, L'+', C_BORDER);

        if (searching) {
            const wchar_t* prompt = L" Search: ";
            surf.text(1, 1, prompt, C_SEARCH_K);
            int px = 1 + (int)wcslen(prompt);

            std::wstring display = searchBuf + L'_';
            int avail = W - px - 2;
            if ((int)display.size() > avail) display = display.substr(display.size() - avail);
            surf.text(px, 1, display.c_str(), C_SEARCH);

            wchar_t cnt[64];
            swprintf(cnt, 64, L" [%d/%d] ESC=clear  ", (int)view.size(), (int)procs.size());
            int cx = W - (int)wcslen(cnt) - 1;
            if (cx > px + (int)display.size() + 1)
                surf.text(cx, 1, cnt, C_DIM);
        }
        else {
            const int colMark = 2;
            const int colPid = 6;
            const int colName = 14;
            const int colWin = 40;
            surf.text(colMark, 1, L"SEL", C_HEADER);
            surf.text(colPid, 1, L"PID", C_HEADER);
            surf.text(colName, 1, L"MODULE", C_HEADER);
            surf.text(colWin, 1, L"WINDOW", C_HEADER);

            if (!searchBuf.empty()) {
                std::wstring hint = L"  filter: \"" + searchBuf + L"\"  [/] to edit  [ESC] to clear";
                int hx = 2;
                int avail = W - hx - 2;
                if ((int)hint.size() > avail) hint = hint.substr(0, avail);
                surf.text(hx, 1, hint.c_str(), C_SEARCH_K);
            }
        }

        int sep = list_bottom();
        surf.hline(1, sep, W - 2, L'-', C_BORDER);
        surf.put(0, sep, L'+', C_BORDER);
        surf.put(W - 1, sep, L'+', C_BORDER);

        const int colMark = 2;
        const int colPid = 6;
        const int colName = 14;
        const int colWin = 40;

        int lh = list_height();
        int rows = (int)view.size();
        clamp_scroll();

        for (int i = 0; i < lh; ++i) {
            int vi = scroll + i;
            int row = list_top() + i;
            if (vi >= rows) break;

            int idx = view[vi];
            const auto& p = procs[idx];

            bool isCur = (vi == cursor);
            bool isMark = (idx == marked);

            WORD rowAttr = isMark ? C_MARKED : (isCur ? C_HOVER : 0);
            if (isCur || isMark)
                surf.hline(1, row, W - 2, L' ', rowAttr);

            WORD boxAttr = isMark ? C_MARK_BOX : (isCur ? C_HOVER : C_DIM);
            surf.text(colMark, row, isMark ? L"[*]" : L"[ ]", boxAttr);

            wchar_t pid[16];
            swprintf(pid, 16, L"%5lu", p.pid);
            surf.text(colPid, row, pid, (isCur || isMark) ? rowAttr : C_PID);

            std::wstring nm = surf.fit(p.name, 24);
            WORD nmCol = (isCur || isMark) ? rowAttr
                : (p.hasWindow ? C_WINDOW : C_NORMAL);
            surf.text(colName, row, nm.c_str(), nmCol);

            if (p.hasWindow) {
                int avail = W - colWin - 2;
                std::wstring wt = surf.fit(p.window, avail);
                surf.text(colWin, row, wt.c_str(), (isCur || isMark) ? rowAttr : C_DIM);
            }

            if (!isCur && !isMark) {
                surf.put(0, row, L'|', C_BORDER);
                surf.put(W - 1, row, L'|', C_BORDER);
            }
        }

        if (rows > lh) {
            int barH = lh;
            int thumbH = std::max(1, barH * lh / rows);
            int thumbY = (rows > 1) ? (scroll * (barH - thumbH) / (rows - lh)) : 0;
            for (int i = 0; i < barH; ++i)
                surf.put(W - 2, list_top() + i,
                    (i >= thumbY && i < thumbY + thumbH) ? L'#' : L'.',
                    C_BORDER);
        }

        int SR = status_rows(W);
        int HR = hint_rows(W);

        int row_dll = H - 1;
        int row_status = H - 1 - SR;
        int row_hints = H - 1 - SR - HR;

        {
            int sx = 2;
            std::wstring dp = dllPath.empty() ? L"(none)" : dllPath.filename().wstring();
            std::wstring dllLabel = L"dll:" + dp + L" ";
            surf.text(sx, row_dll, dllLabel.c_str(), C_STATUS_K);
            sx += (int)dllLabel.size();

            if (marked >= 0 && marked < (int)procs.size()) {
                std::wstring mn = L"marked: " + procs[marked].name
                    + L" (PID " + std::to_wstring(procs[marked].pid) + L")";
                int avail = W - sx - 2;
                if ((int)mn.size() > avail) mn = mn.substr(0, avail);
                surf.text(sx, row_dll, mn.c_str(), C_INJECT);
            }
            else {
                surf.text(sx, row_dll, L"no selection", C_DIM);
            }
        }

        if (!status.empty()) {
            int usable_s = W - 4;
            if (usable_s < 1) usable_s = 1;
            std::wstring msg = status;
            for (int r = 0; r < SR && !msg.empty(); ++r) {
                std::wstring line = msg.substr(0, (size_t)usable_s);
                msg = (msg.size() > (size_t)usable_s) ? msg.substr((size_t)usable_s) : L"";
                surf.text(2, row_status + r, line.c_str(), statusColor);
            }
        }

        {
            struct HintToken { const wchar_t* key; const wchar_t* val; };
            HintToken tokens[] = {
                {L"[Up/Dn]",   L"move"},
                {L"[PgUp/Dn]", L"page"},
                {L"[Rt]",      L"mark"},
                {L"[Lt]",      L"unmark"},
                {L"[I]",       L"inject"},
                {L"[E]",       L"eject"},
                {L"[D]",       L"set dll"},
                {L"[/]",       L"search"},
                {L"[Q]",       L"quit"},
                {L"[R]",       L"Run as Admin"},
            };
            int nTokens = isAdmin ? 9 : 10;
            int usable_h = W - 3;
            int cur_x = 2, cur_row = 0;
            for (int i = 0; i < nTokens; ++i) {
                int w = (int)(wcslen(tokens[i].key) + wcslen(tokens[i].val)) + 1;
                if (cur_x + w > usable_h && cur_x > 2) { ++cur_row; cur_x = 2; }
                int sr = row_hints + cur_row;
                surf.text(cur_x, sr, tokens[i].key, C_STATUS_K);
                surf.text(cur_x + (int)wcslen(tokens[i].key), sr, tokens[i].val, C_STATUS_V);
                cur_x += w;
            }
        }

        surf.flush();
    }

    void do_inject() {
        if (dllPath.empty()) {
            set_status(L"No DLL selected - press D to browse", C_ERR);
            return;
        }
        if (marked < 0 || marked >= (int)procs.size()) {
            set_status(L"No process marked - use Right arrow to mark", C_ERR);
            return;
        }

        const auto& p = procs[marked];

        HANDLE hproc = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ |
            PROCESS_QUERY_INFORMATION,
            FALSE, p.pid);

        if (!hproc) {
            wchar_t buf[64];
            swprintf(buf, 64, L"OpenProcess failed: %lu", GetLastError());
            set_status(buf, C_ERR);
            return;
        }

        HMODULE      hdll = nullptr;
        dll::error_t err = dll::inject(hproc, dllPath.string().c_str(), &hdll);
        CloseHandle(hproc);

        if (err) {
            auto         es = dll::error_string(err);
            std::wstring ws(es.begin(), es.end());
            set_status(L"inject error: " + ws + L" (" + std::to_wstring((int)err) + L")", C_ERR);
            return;
        }
        if (!hdll) {
            set_status(L"inject error: LoadLibrary returned null", C_ERR);
            return;
        }

        wchar_t buf[128];
        swprintf(buf, 128, L"Injected into %s (PID %lu) hDLL=0x%p",
            p.name.c_str(), p.pid, hdll);
        set_status(buf, C_OK);
    }

    void do_eject() {
        if (dllPath.empty()) {
            set_status(L"No DLL selected - press D to browse", C_ERR);
            return;
        }
        if (marked < 0 || marked >= (int)procs.size()) {
            set_status(L"No process marked - use Right arrow to mark", C_ERR);
            return;
        }

        const auto& p = procs[marked];

        HANDLE hproc = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ |
            PROCESS_QUERY_INFORMATION,
            FALSE, p.pid);

        if (!hproc) {
            wchar_t buf[64];
            swprintf(buf, 64, L"OpenProcess failed: %lu", GetLastError());
            set_status(buf, C_ERR);
            return;
        }

        HMODULE mods[1024];
        DWORD   needed = 0;
        HMODULE target = nullptr;

        if (EnumProcessModules(hproc, mods, sizeof(mods), &needed)) {
            DWORD mc = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < mc; ++i) {
                wchar_t name[MAX_PATH] = {};
                if (!GetModuleFileNameExW(hproc, mods[i], name, MAX_PATH))
                    continue;
                if (fs::path(name) == dllPath) { target = mods[i]; break; }
            }
        }

        if (!target) {
            CloseHandle(hproc);
            set_status(L"eject error: module not found in target process", C_ERR);
            return;
        }

        dll::error_t err = dll::eject(hproc, target);
        CloseHandle(hproc);

        if (err) {
            auto         es = dll::error_string(err);
            std::wstring ws(es.begin(), es.end());
            set_status(L"eject error: " + ws + L" (" + std::to_wstring((int)err) + L")", C_ERR);
            return;
        }

        wchar_t buf[128];
        swprintf(buf, 128, L"Ejected from %s (PID %lu)", p.name.c_str(), p.pid);
        set_status(buf, C_OK);
    }

    void run() {
        surf.init();
        refresh_procs();

        isAdmin = dll::helper::is_administrator();

        dllPath = load_dll_path();
        if (!dllPath.empty())
            set_status(L"Loaded DLL: " + dllPath.filename().wstring(), C_STATUS_V);
        else if (!isAdmin)
            set_status(L"Not running as administrator - some processes may be inaccessible", C_WARN);
        else
            set_status(L"Ready", C_NORMAL);

        HANDLE hin = GetStdHandle(STD_INPUT_HANDLE);
        SetConsoleMode(hin, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);

        draw();

        DWORD lastRefresh = GetTickCount();

        while (true) {
            DWORD now = GetTickCount();
            DWORD elapsed = now - lastRefresh;
            DWORD timeout = (elapsed >= 500) ? 0 : (500 - elapsed);

            DWORD wait = WaitForSingleObject(hin, timeout);

            if (wait == WAIT_TIMEOUT) {
                if (!searching) {
                    refresh_procs();
                    lastRefresh = GetTickCount();
                }
                draw();
                continue;
            }

            INPUT_RECORD ir;
            DWORD        nr = 0;
            ReadConsoleInputW(hin, &ir, 1, &nr);

            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                auto vk = ir.Event.KeyEvent.wVirtualKeyCode;
                auto ch = ir.Event.KeyEvent.uChar.UnicodeChar;

                if (searching) {
                    if (vk == VK_ESCAPE) {
                        searching = false;
                        searchBuf.clear();
                        rebuild_view();
                        set_status(L"Search cleared", C_DIM);
                    }
                    else if (vk == VK_RETURN) {
                        searching = false;
                        if (searchBuf.empty())
                            set_status(L"", C_NORMAL);
                        else {
                            wchar_t buf[128];
                            swprintf(buf, 128, L"Filter: \"%s\"  (%d results)", searchBuf.c_str(), (int)view.size());
                            set_status(buf, C_SEARCH_K);
                        }
                    }
                    else if (vk == VK_BACK) {
                        if (!searchBuf.empty()) {
                            searchBuf.pop_back();
                            rebuild_view();
                        }
                    }
                    else if (vk == VK_UP) {
                        if (cursor > 0) --cursor;
                    }
                    else if (vk == VK_DOWN) {
                        if (cursor < (int)view.size() - 1) ++cursor;
                    }
                    else if (ch >= L' ') {
                        searchBuf += ch;
                        rebuild_view();
                        cursor = 0;
                        scroll = 0;
                    }

                    draw();
                    continue;
                }

                auto lch = towlower(ch);

                if (vk == VK_UP) {
                    if (cursor > 0) --cursor;
                    set_status(L"");
                }
                else if (vk == VK_DOWN) {
                    if (cursor < (int)view.size() - 1) ++cursor;
                    set_status(L"");
                }
                else if (vk == VK_RIGHT) {
                    if (!view.empty()) {
                        marked = view[cursor];
                        set_status(L"");
                    }
                }
                else if (vk == VK_LEFT) {
                    marked = -1;
                    set_status(L"");
                }
                else if (vk == VK_PRIOR) {
                    cursor = std::max(0, cursor - list_height());
                }
                else if (vk == VK_NEXT) {
                    cursor = std::min((int)view.size() - 1, cursor + list_height());
                }
                else if (lch == L'r' && !isAdmin) {
                    relaunch_as_admin();
                }
                else if (ch == L'/') {
                    searching = true;
                    set_status(L"");
                }
                else if (vk == VK_ESCAPE && !searchBuf.empty()) {
                    searchBuf.clear();
                    rebuild_view();
                    set_status(L"Filter cleared", C_DIM);
                }
                else if (lch == L'd') {
                    SetConsoleMode(hin, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
                    try {
                        fs::path p = SelectFile();
                        if (!p.empty()) {
                            dllPath = p;
                            save_dll_path(dllPath);
                            set_status(L"DLL: " + dllPath.filename().wstring(), C_OK);
                        }
                        else {
                            set_status(L"Browse cancelled", C_DIM);
                        }
                    }
                    catch (...) {
                        set_status(L"File picker error", C_ERR);
                    }
                    SetConsoleMode(hin, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);
                }
                else if (lch == L'i') {
                    do_inject();
                }
                else if (lch == L'e') {
                    do_eject();
                }
                else if (lch == L'q' || vk == VK_ESCAPE) {
                    break;
                }

                draw();
            }
            else if (ir.EventType == WINDOW_BUFFER_SIZE_EVENT) {
                surf.init();
                draw();
            }
        }

        CONSOLE_CURSOR_INFO cci{ 10, TRUE };
        SetConsoleCursorInfo(surf.hout, &cci);
    }
};

int main()
{
    nt::init();
    dll::helper::enable_debug_privilege();

    App app;
    app.run();

    return 0;
}