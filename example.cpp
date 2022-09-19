#include <Windows.h>
#include "SuperHook.h"

SuperHook* g_pSuperHook;

DWORD __stdcall Hooked_GetCurrentProcessId()
{
    // Do something

    // Call real function with parameters
    DWORD dwProcessId = reinterpret_cast<decltype(GetCurrentProcessId)*>(g_pSuperHook->ClonedFunction("GetCurrentProcessId"))();

    // Do something
    return 0;
}

DWORD __stdcall Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // Do something

    // Call real function with parameters
    DWORD dwResult = reinterpret_cast<decltype(MessageBoxA)*>(g_pSuperHook->ClonedFunction("MessageBoxA"))(hWnd, "MessageBox Hooked!", "MessageBox Hooked!", uType);

    // Do something
    return dwResult;
}

void initlize_hooking()
{
    g_pSuperHook = new SuperHook();

    g_pSuperHook->HookFunction("kernel32.dll", "GetCurrentProcessId", reinterpret_cast<UINT_PTR>(Hooked_GetCurrentProcessId), SUPERHOOKTYPE_ABSOLUTEJMP);

    g_pSuperHook->HookFunction("user32.dll", "MessageBoxA", reinterpret_cast<UINT_PTR>(Hooked_MessageBoxA), SUPERHOOKTYPE_ABSOLUTEJMP);

}

int main()
{
    LoadLibraryA("user32.dll");

    initlize_hooking();

    printf("Hooked Process ID %d\n", GetCurrentProcessId());


    MessageBoxA(NULL, "hello", "hello", 0);

    return 0;
}