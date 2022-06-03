#include <Windows.h>
#include "SuperHook.hpp"


super_hook<decltype(&MessageBoxA)> x;

int WINAPI Hooked_MessageBoxA(HWND h, LPCSTR a, LPCSTR b, UINT t)
{
	x.get_function()(0, "HACKED", "HACKED", 0);
	return 0;
}


int main()
{
	MessageBoxA(0, "YS - First Message", "YS - First Message", 0);


	x.init((UINT_PTR)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA"));
	x.absolutejmp_hook((UINT_PTR)Hooked_MessageBoxA);

	MessageBoxA(0, "YS - Second Message", "YS - Second Message", 0);

	x.remove_hook();
	MessageBoxA(0, "YS - Third Message", "YS - Third Message", 0);



	return 0;
}


