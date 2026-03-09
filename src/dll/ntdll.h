#pragma once
#include <Windows.h>

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    LPVOID AttributeList
    );

namespace nt
{

    inline NtCreateThreadEx_t NtCreateThreadEx = nullptr;

    inline bool init()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll)
            return false;

        NtCreateThreadEx =
            (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");

        return NtCreateThreadEx != nullptr;
    }

}