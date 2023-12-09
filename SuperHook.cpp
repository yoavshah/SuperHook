/*
	Created by Yoav Shaharabani (github.com/yoavshah)
	Use with your own risk and care.
	DO NOT USE FOR MALICIOUS PURPOSES!
	FOLLOW ME ON GITHUB AND BUY ME A COFFEE
*/

#pragma once
#include "SuperHook.h"

namespace SuperHookUtils
{
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	BOOL IsWow64()
	{
		BOOL bIsWow64 = FALSE;

		//IsWow64Process is not available on all supported versions of Windows.
		//Use GetModuleHandle to get a handle to the DLL that contains the function
		//and GetProcAddress to get a pointer to the function if available.

		LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
			GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

		if (NULL != fnIsWow64Process)
		{
			if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
			{
				return FALSE;
			}
		}
		return bIsWow64;
	}

	DWORD CalculateProtectionFlags(unsigned long ulSectionCharacteristics)
	{
		DWORD dwProtectionFlags = 0;

		if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_EXECUTE_READWRITE;
		}

		if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_EXECUTE_WRITECOPY;
		}

		if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_EXECUTE_READ;
		}

		if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_EXECUTE;
		}

		if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_READWRITE;
		}

		if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_WRITECOPY;
		}

		if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_READONLY;
		}

		if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
			&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
		{
			dwProtectionFlags |= PAGE_NOACCESS;
		}


		if (ulSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
		{
			dwProtectionFlags |= PAGE_NOCACHE;
		}

		return dwProtectionFlags;

	}

}

namespace SuperHookHooks
{
	bool absolutejmp_hook(UINT_PTR pFunctionToHook, UINT_PTR pMaliciousFunction, unsigned int* uNumberOfBytesOverwritten)
	{
		bool bSucceed = true;
		if (uNumberOfBytesOverwritten == NULL)
		{
			return false;
		}

		*uNumberOfBytesOverwritten = 0;


#ifdef _WIN64
		DWORD dwOldProtect;
		VirtualProtect((LPVOID)pFunctionToHook, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		InterlockedExchange8((char*)pFunctionToHook, '\xC3');

		// jmp rax.
		*(char*)(pFunctionToHook + 10) = '\xFF';
		*(char*)(pFunctionToHook + 11) = '\xE0';

		// movabs rax, pMalicousFunction
		*(ULONG_PTR*)(pFunctionToHook + 2) = pMaliciousFunction;
		*(char*)(pFunctionToHook + 1) = '\xB8';
		InterlockedExchange8((char*)pFunctionToHook, '\x48');

		// We now changed the function to run
		// mov rax, pMalicousFunction
		// jmp rax

		VirtualProtect((LPVOID)pFunctionToHook, 12, dwOldProtect, &dwOldProtect);
		*uNumberOfBytesOverwritten = 12;

#elif _WIN32
		DWORD dwOldProtect;
		VirtualProtect((LPVOID)pFunctionToHook, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		InterlockedExchange8((char*)pFunctionToHook, '\xC3');

		// jmp eax.
		*(char*)(pFunctionToHook + 5) = '\xFF';
		*(char*)(pFunctionToHook + 6) = '\xE0';

		// mov eax, pMalicousFunction
		*(ULONG_PTR*)(pFunctionToHook + 1) = pMaliciousFunction;
		InterlockedExchange8((char*)pFunctionToHook, '\xB8');

		// We now changed the function to run
		// mov eax, pMalicousFunction
		// jmp eax

		VirtualProtect((LPVOID)pFunctionToHook, 7, dwOldProtect, &dwOldProtect);
		*uNumberOfBytesOverwritten = 7;
#endif

		
		return bSucceed;
	}
}


SuperHookModule::SuperHookModule(UINT_PTR pModule) : m_pModule(pModule), m_pCloneModule(NULL), m_uCloneModuleSize(0)
{
	this->CloneModule();
}

SuperHookModule::~SuperHookModule()
{
	if (this->m_pCloneModule)
	{
		VirtualFree(reinterpret_cast<LPVOID>(this->m_pCloneModule), 0, MEM_RELEASE);
	}
}

bool SuperHookModule::CloneModule()
{
	DWORD dwOldProtect;

	SYSTEM_INFO sysInfo;
	this->m_pCloneModule = NULL;

	this->m_uCloneModuleSize = reinterpret_cast<PIMAGE_NT_HEADERS>(this->m_pModule + reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_pModule)->e_lfanew)->OptionalHeader.SizeOfImage;
		
	this->m_pCloneModule = reinterpret_cast<UINT_PTR>(VirtualAlloc(NULL, this->m_uCloneModuleSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!this->m_pCloneModule)
	{
		return false;
	}

	for (size_t i = 0; i < this->m_uCloneModuleSize; i++)
	{
		reinterpret_cast<unsigned char*>(this->m_pCloneModule)[i] = 0x00;
	}

	if (!SuperHookUtils::IsWow64())
	{
		for (size_t i = 0; i < this->m_uCloneModuleSize; i++)
		{
			reinterpret_cast<unsigned char*>(this->m_pCloneModule)[i] = reinterpret_cast<unsigned char*>(this->m_pModule)[i];
		}
	}
	else
	{
		// Look at kernel32.dll under wow64, fking stupid fuck on microsoft
		GetSystemInfo(&sysInfo);
		for (size_t i = 0; i < this->m_uCloneModuleSize; i += sysInfo.dwPageSize)
		{
			MEMORY_BASIC_INFORMATION mbi;

			VirtualQuery(reinterpret_cast<unsigned char*>(this->m_pModule) + i, &mbi, sizeof(mbi));

			if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)
			{
				for (size_t j = 0; j < sysInfo.dwPageSize; j++)
				{
					reinterpret_cast<unsigned char*>(this->m_pCloneModule)[i + j] = reinterpret_cast<unsigned char*>(this->m_pModule)[i + j];
				}
			}
		}

	}


	UINT_PTR pucCurrentSection;
	unsigned int uNumberOfSections;
	VirtualProtect(reinterpret_cast<LPVOID>(this->m_pCloneModule), this->m_uCloneModuleSize, PAGE_READONLY, &dwOldProtect);

	uNumberOfSections = reinterpret_cast<PIMAGE_NT_HEADERS>(this->m_pModule + reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_pModule)->e_lfanew)->FileHeader.NumberOfSections;
	pucCurrentSection = reinterpret_cast<UINT_PTR>(IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(this->m_pModule + reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_pModule)->e_lfanew)));
	for (size_t i = 0; i < uNumberOfSections; i++)
	{
		DWORD dwProtectionFlag = 0;

		dwProtectionFlag = SuperHookUtils::CalculateProtectionFlags(reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Characteristics);

		VirtualProtect(reinterpret_cast<LPVOID>(this->m_pCloneModule + reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->VirtualAddress), reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Misc.VirtualSize, dwProtectionFlag, &dwOldProtect);

	}

	VirtualProtect(reinterpret_cast<LPVOID>(this->m_pCloneModule), this->m_uCloneModuleSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);


	return true;

}

UINT_PTR SuperHookModule::GetOriginalModule() { return this->m_pModule; }
UINT_PTR SuperHookModule::GetClonedModule() { return this->m_pCloneModule; }


SuperHookFunction::SuperHookFunction(SuperHookModule* pSuperHookModule, UINT_PTR pHookedFunctionPointer, UINT_PTR pMaliciousFunctionPointer) : m_pSuperHookModule(pSuperHookModule), m_pHookedFunctionPointer(pHookedFunctionPointer), m_pMaliciousFunctionPointer(pMaliciousFunctionPointer), m_pClonedFunctionPointer(NULL), m_IsHooked(false), m_uNumberOfBytesChanged(0)
{
	this->m_pClonedFunctionPointer = pHookedFunctionPointer - pSuperHookModule->GetOriginalModule() + pSuperHookModule->GetClonedModule();
} 

SuperHookFunction::~SuperHookFunction()
{
	
}

bool SuperHookFunction::SetHook(SuperHookType hhtHookType)
{
	bool bHookSucceed = false;
	unsigned int uNumberOfBytesChanged = 0;

	if (this->m_IsHooked)
		return false;
		
	switch (hhtHookType)
	{
	case SUPERHOOKTYPE_ABSOLUTEJMP:
		bHookSucceed = SuperHookHooks::absolutejmp_hook(this->m_pHookedFunctionPointer, m_pMaliciousFunctionPointer, &uNumberOfBytesChanged);
		break;

	case SUPERHOOKTYPE_RET:
		break;

	default:
		break;
	}

	if (bHookSucceed)
	{
		FlushInstructionCache((HANDLE)-1, NULL, 0);
	}

	this->m_IsHooked = bHookSucceed;
	this->m_uNumberOfBytesChanged= uNumberOfBytesChanged;
}

bool SuperHookFunction::UnHook()
{
	if (!this->m_IsHooked)
		return false;


	DWORD dwOldProtect;
	VirtualProtect(reinterpret_cast<LPVOID>(this->m_pHookedFunctionPointer), this->m_uNumberOfBytesChanged, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	InterlockedExchange8((char*)this->m_pHookedFunctionPointer, '\xC3');


	for (size_t i = 1; i < this->m_uNumberOfBytesChanged; i++)
	{
		reinterpret_cast<unsigned char*>(this->m_pHookedFunctionPointer)[i] = reinterpret_cast<unsigned char*>(this->m_pClonedFunctionPointer)[i];
	}

	InterlockedExchange8(reinterpret_cast<char*>(this->m_pHookedFunctionPointer), reinterpret_cast<unsigned char*>(this->m_pClonedFunctionPointer)[0]);

	VirtualProtect(reinterpret_cast<LPVOID>(this->m_pHookedFunctionPointer), this->m_uNumberOfBytesChanged, dwOldProtect, &dwOldProtect);

	this->m_IsHooked = false;
	return true;
}


bool SuperHookFunction::IsHooked()
{
	return this->m_IsHooked;
}


UINT_PTR SuperHookFunction::GetOriginalFunction()
{
	return this->m_pClonedFunctionPointer;
}

