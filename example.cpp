#include <Windows.h>
#include "SuperHook.h"

SuperHookModule* g_pSuperHookModule;
SuperHookFunction* g_pSuperHookFunctionGetCurrentProcessId;

DWORD __stdcall Hooked_GetCurrentProcessId()
{
    // Do something

    // Call real function with parameters
    DWORD dwProcessId = reinterpret_cast<decltype(GetCurrentProcessId)*>(g_pSuperHookFunctionGetCurrentProcessId->GetOriginalFunction())();

    // Do something

    // Return other value

    return dwProcessId + 0x1337;
}

void initlize_hooking()
{
    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");
    g_pSuperHookModule = new SuperHookModule(reinterpret_cast<UINT_PTR>(kernel32));

    g_pSuperHookFunctionGetCurrentProcessId = new SuperHookFunction(g_pSuperHookModule, reinterpret_cast<UINT_PTR>(GetProcAddress(kernel32, "GetCurrentProcessId")), reinterpret_cast<UINT_PTR>(Hooked_GetCurrentProcessId));

    g_pSuperHookFunctionGetCurrentProcessId->SetHook(SUPERHOOKTYPE_ABSOLUTEJMP);
}

int main()
{
    printf("Process ID %d\n", GetCurrentProcessId());

    initlize_hooking();

    printf("Hooked Process ID %d\n", GetCurrentProcessId());

    g_pSuperHookFunctionGetCurrentProcessId->UnHook();

    printf("Unhooked Process ID %d\n", GetCurrentProcessId());

    return 0;
}