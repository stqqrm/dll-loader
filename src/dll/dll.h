#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <format>
#include "ntdll.h"

namespace dll
{
    namespace fs = std::filesystem;

    enum error_t
    {
        DLL_SUCCESS = 0,
        DLL_INVALID_HANDLE,
        DLL_PROCESS_NOT_FOUND,
        DLL_OPEN_PROCESS_FAIL,
        DLL_ARCH_MISMATCH,
        DLL_INVALID_PATH,
        DLL_ALLOC_FAIL,
        DLL_WRITE_FAIL,
        DLL_THREAD_FAIL,
        DLL_THREAD_RETURN_CODE_FAIL,
        DLL_WAIT_FAIL,
        DLL_FOUND_IN_PROCESS,
        DLL_NOT_FOUND_IN_PROCESS,
    };

    inline std::wstring error_string(error_t err)
    {
        switch (err)
        {
        case DLL_SUCCESS: return L"DLL_SUCCESS";
        case DLL_INVALID_HANDLE: return L"DLL_INVALID_HANDLE";
        case DLL_PROCESS_NOT_FOUND: return L"DLL_PROCESS_NOT_FOUND";
        case DLL_OPEN_PROCESS_FAIL: return L"DLL_OPEN_PROCESS_FAIL";
        case DLL_ARCH_MISMATCH: return L"DLL_ARCH_MISMATCH";
        case DLL_INVALID_PATH: return L"DLL_INVALID_PATH";
        case DLL_ALLOC_FAIL: return L"DLL_ALLOC_FAIL";
        case DLL_WRITE_FAIL: return L"DLL_WRITE_FAIL";
        case DLL_THREAD_FAIL: return L"DLL_THREAD_FAIL";
        case DLL_THREAD_RETURN_CODE_FAIL: return L"DLL_THREAD_RETURN_CODE_FAIL";
        case DLL_WAIT_FAIL: return L"DLL_WAIT_FAIL";
        case DLL_FOUND_IN_PROCESS: return L"DLL_FOUND_IN_PROCESS";
        case DLL_NOT_FOUND_IN_PROCESS: return L"DLL_NOT_FOUND_IN_PROCESS";
        default:
            return std::format(L"UNKNOWN_ERROR 0x{:X}", (int)err);
        }
    }

    namespace helper
    {
        inline bool is_administrator()
        {
            BOOL    result = FALSE;
            HANDLE  token = nullptr;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
                return false;

            TOKEN_ELEVATION elevation = {};
            DWORD           size = sizeof(elevation);

            if (GetTokenInformation(token, TokenElevation, &elevation, size, &size))
                result = elevation.TokenIsElevated;

            CloseHandle(token);
            return result;
        }

        inline bool enable_debug_privilege()
        {
            HANDLE token;

            if (!OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &token))
                return false;

            TOKEN_PRIVILEGES tp{};
            LUID luid;

            if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid))
                return false;

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            tp.Privileges[0].Luid = luid;

            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);

            CloseHandle(token);
            return true;
        }

        inline DWORD get_pid(std::wstring exe)
        {
            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return 0;

            DWORD pid = 0;

            if (Process32FirstW(snap, &entry))
            {
                do
                {
                    if (!_wcsicmp(entry.szExeFile, exe.c_str()))
                    {
                        pid = entry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snap, &entry));
            }

            CloseHandle(snap);
            return pid;
        }

        inline bool get_module_info(HANDLE proc, fs::path dll_path, LPMODULEINFO mi)
        {
            HMODULE mods[1024];
            DWORD   needed = 0;

            if (!EnumProcessModules(proc, mods, sizeof(mods), &needed))
                return false;

            DWORD count = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count; ++i)
            {
                wchar_t name[MAX_PATH] = {};
                if (!GetModuleFileNameExW(proc, mods[i], name, MAX_PATH))
                    continue;

                if (fs::path(name) == dll_path)
                    return GetModuleInformation(proc, mods[i], mi, sizeof(MODULEINFO));
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
                if (mods[i] == mod)
                    return true;

            return false;
        }

        inline bool check_arch(HANDLE process)
        {
            BOOL self = FALSE;
            BOOL target = FALSE;

            IsWow64Process(GetCurrentProcess(), &self);
            IsWow64Process(process, &target);

            return self == target;
        }
    }

    inline error_t inject(
        HANDLE proc,
        const fs::path& dll_path,
        HMODULE* mod_out)
    {
        if (!proc || proc == INVALID_HANDLE_VALUE) {
            return DLL_INVALID_HANDLE;
        }

        if (!fs::exists(dll_path))
            return DLL_INVALID_PATH;

        if (!helper::check_arch(proc))
            return DLL_ARCH_MISMATCH;

        MODULEINFO mi;

        if (helper::get_module_info(proc, dll_path, &mi)) {
            return DLL_FOUND_IN_PROCESS;
        }

        std::wstring path = dll_path.wstring();
        SIZE_T size = (path.size() + 1) * sizeof(wchar_t);

        void* remote = VirtualAllocEx(
            proc,
            nullptr,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (!remote)
            return DLL_ALLOC_FAIL;

        if (!WriteProcessMemory(proc, remote, path.c_str(), size, nullptr)) {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            return DLL_WRITE_FAIL;
        }

        auto load =
            (LPTHREAD_START_ROUTINE)GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"),
                "LoadLibraryW");

        HANDLE thread;

        NTSTATUS status = nt::NtCreateThreadEx(
            &thread,
            THREAD_ALL_ACCESS,
            nullptr,
            proc,
            load,
            remote,
            FALSE,
            0,
            0,
            0,
            nullptr);

        if (!NT_SUCCESS(status)) {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            return DLL_THREAD_FAIL;
        }

        WaitForSingleObject(thread, INFINITE);

        DWORD code;
        GetExitCodeThread(thread, &code);
        CloseHandle(thread);

        if (!code) {
            VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
            return DLL_THREAD_RETURN_CODE_FAIL;
        }

        if (mod_out)
            *mod_out = (HMODULE)code;

        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return DLL_SUCCESS;
    }

    inline error_t eject(HANDLE proc, HMODULE mod) {

        if (!helper::does_module_exist(proc, mod)) {
            return DLL_NOT_FOUND_IN_PROCESS;
        }

        auto free_lib =
            (LPTHREAD_START_ROUTINE)GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"),
                "FreeLibrary");

        HANDLE thread;

        NTSTATUS status = nt::NtCreateThreadEx(
            &thread,
            THREAD_ALL_ACCESS,
            nullptr,
            proc,
            free_lib,
            mod,
            FALSE,
            0,
            0,
            0,
            nullptr);

        if (!NT_SUCCESS(status))
            return DLL_THREAD_FAIL;

        WaitForSingleObject(thread, INFINITE);

        DWORD code;
        GetExitCodeThread(thread, &code);
        CloseHandle(thread);
        
        if (!code) {
            return DLL_THREAD_RETURN_CODE_FAIL;
        }
        
        return DLL_SUCCESS;
    }
} // namespace dll