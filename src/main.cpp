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
        put(x, y, L'\x250C', attr);
        put(x + rw - 1, y, L'\x2510', attr);
        put(x, y + rh - 1, L'\x2514', attr);
        put(x + rw - 1, y + rh - 1, L'\x2518', attr);
        for (int i = 1; i < rw - 1; ++i) {
            put(x + i, y, L'\x2500', attr);
            put(x + i, y + rh - 1, L'\x2500', attr);
        }
        for (int i = 1; i < rh - 1; ++i) {
            put(x, y + i, L'\x2502', attr);
            put(x + rw - 1, y + i, L'\x2502', attr);
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

struct App {
    Surface                surf;
    std::vector<ProcEntry> procs;
    int                    cursor = 0;
    int                    scroll = 0;
    int                    marked = -1;
    fs::path               dllPath;
    std::wstring           status;
    WORD                   statusColor = C_NORMAL;
    bool                   isAdmin = false;

    void set_status(const std::wstring& s, WORD col = C_NORMAL) {
        status = s;
        statusColor = col;
    }

    void refresh_procs() {
        DWORD cursorPid = (cursor >= 0 && cursor < (int)procs.size())
            ? procs[cursor].pid : 0;
        DWORD markedPid = (marked >= 0 && marked < (int)procs.size())
            ? procs[marked].pid : 0;

        procs = enumerate_processes();

        cursor = 0;
        marked = -1;

        for (int i = 0; i < (int)procs.size(); ++i) {
            if (cursorPid != 0 && procs[i].pid == cursorPid) cursor = i;
            if (markedPid != 0 && procs[i].pid == markedPid) marked = i;
        }
    }

    int list_top()    const { return 3; }
    int list_bottom() const { return surf.h - 4; }
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

        // title + optional admin warning in header
        if (!isAdmin) {
            const wchar_t* warn = L" ! NOT ADMINISTRATOR ! ";
            int wx = (W - (int)wcslen(warn)) / 2;
            surf.text(wx, 0, warn, C_WARN);
        }
        else {
            const wchar_t* title = L" DLL Injector ";
            surf.text((W - (int)wcslen(title)) / 2, 0, title, C_HEADER);
        }

        surf.hline(1, 2, W - 2, L'\x2500', C_BORDER);
        surf.put(0, 2, L'\x251C', C_BORDER);
        surf.put(W - 1, 2, L'\x2524', C_BORDER);

        const int colMark = 2;
        const int colPid = 6;
        const int colName = 14;
        const int colWin = 40;

        surf.text(colMark, 1, L"SEL", C_HEADER);
        surf.text(colPid, 1, L"PID", C_HEADER);
        surf.text(colName, 1, L"MODULE", C_HEADER);
        surf.text(colWin, 1, L"WINDOW", C_HEADER);

        int sep = H - 3;
        surf.hline(1, sep, W - 2, L'\x2500', C_BORDER);
        surf.put(0, sep, L'\x251C', C_BORDER);
        surf.put(W - 1, sep, L'\x2524', C_BORDER);

        int lh = list_height();
        int rows = (int)procs.size();
        clamp_scroll();

        for (int i = 0; i < lh; ++i) {
            int idx = scroll + i;
            int row = list_top() + i;
            if (idx >= rows) break;

            const auto& p = procs[idx];
            bool        isCur = (idx == cursor);
            bool        isMark = (idx == marked);

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
                surf.put(0, row, L'\x2502', C_BORDER);
                surf.put(W - 1, row, L'\x2502', C_BORDER);
            }
        }

        // scrollbar
        if (rows > lh) {
            int barH = lh;
            int thumbH = std::max(1, barH * lh / rows);
            int thumbY = (rows > 1) ? (scroll * (barH - thumbH) / (rows - lh)) : 0;
            for (int i = 0; i < barH; ++i)
                surf.put(W - 2, list_top() + i,
                    (i >= thumbY && i < thumbY + thumbH) ? L'\x2588' : L'\x2591',
                    C_BORDER);
        }

        // status bar
        int sy1 = H - 2;
        int sy2 = H - 1;

        auto hint = [&](int& x, int row, const wchar_t* key, const wchar_t* val) {
            surf.text(x, row, key, C_STATUS_K);
            x += (int)wcslen(key);
            surf.text(x, row, val, C_STATUS_V);
            x += (int)wcslen(val) + 1;
            };

        int hx = 2;
        hint(hx, sy1, L"[Up/Dn]", L"move");
        hint(hx, sy1, L"[Rt]", L"mark");
        hint(hx, sy1, L"[Lt]", L"unmark");
        hint(hx, sy1, L"[I]", L"inject");
        hint(hx, sy1, L"[E]", L"eject");
        hint(hx, sy1, L"[D]", L"set dll");
        hint(hx, sy1, L"[Q]", L"quit");
        if (!isAdmin) hint(hx, sy1, L"[R]", L"Run as Admin");

        if (!status.empty()) {
            int avail = W - hx - 4;
            std::wstring msg = L"  " + status;
            if ((int)msg.size() > avail) msg = msg.substr(0, avail);
            surf.text(hx + 1, sy1, msg.c_str(), statusColor);
        }

        {
            int sx = 2;
            std::wstring dp = dllPath.empty() ? L"(none)" : dllPath.filename().wstring();
            hint(sx, sy2, L"dll:", (dp + L" ").c_str());

            if (marked >= 0 && marked < (int)procs.size()) {
                std::wstring mn = L"marked: " + procs[marked].name
                    + L" (PID " + std::to_wstring(procs[marked].pid) + L")";
                surf.text(sx + 1, sy2, mn.c_str(), C_INJECT);
            }
            else {
                surf.text(sx + 1, sy2, L"no selection", C_DIM);
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
                refresh_procs();
                lastRefresh = GetTickCount();
                draw();
                continue;
            }

            // input available
            INPUT_RECORD ir;
            DWORD        nr = 0;
            ReadConsoleInputW(hin, &ir, 1, &nr);

            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
                auto vk = ir.Event.KeyEvent.wVirtualKeyCode;
                auto ch = towlower(ir.Event.KeyEvent.uChar.UnicodeChar);

                if (vk == VK_UP) {
                    if (cursor > 0) --cursor;
                    set_status(L"");
                }
                else if (vk == VK_DOWN) {
                    if (cursor < (int)procs.size() - 1) ++cursor;
                    set_status(L"");
                }
                else if (vk == VK_RIGHT) {
                    if (!procs.empty()) {
                        marked = cursor;
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
                    cursor = std::min((int)procs.size() - 1, cursor + list_height());
                }
                else if (ch == L'r' && !isAdmin) {
                    relaunch_as_admin();
                }
                else if (ch == L'd') {
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
                else if (ch == L'i') {
                    do_inject();
                }
                else if (ch == L'e') {
                    do_eject();
                }
                else if (ch == L'q' || vk == VK_ESCAPE) {
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