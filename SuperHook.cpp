/*
	Created by Yoav Shaharabani (github.com/yoavshah)
	Use with your own risk and care.
	DO NOT USE FOR MALICIOUS PURPOSES!
	FOLLOW ME ON GITHUB AND BUY ME A COFFEE
*/

#pragma once
#include "SuperHook.h"

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

SuperHook::SuperHook() : m_bLoaded(false)
{}

SuperHook::~SuperHook()
{
}

bool SuperHook::HookFunction(std::string pszModuleName, std::string pszProcName, UINT_PTR pHookFunction, SuperHookType hhtHookType)
{

	PIMAGE_NT_HEADERS pImageNtHeaders;
	UINT_PTR pFunctionAddressToHook;

	bool bHookSucceed;
	unsigned int uNumberOfBytesOverwritten;

	UINT_PTR pucRealModule;
	UINT_PTR pucClonedModule;


	auto it_functions = this->m_mFunctionsHookData.find(pszProcName);
	if (it_functions != this->m_mFunctionsHookData.end())
	{
		// FOUND, no need to hook
		return false;

	}

	auto it_modules = this->m_mClonedModules.find(pszModuleName);
	if (it_modules != this->m_mClonedModules.end())
	{
		pucRealModule = std::get<1>(it_modules->second);
		pucClonedModule = std::get<0>(it_modules->second);
	}
	else
	{

		pucRealModule = reinterpret_cast<UINT_PTR>(ManualGetModuleByName(pszModuleName));

		pucClonedModule = CloneModule(pucRealModule);

		// ["module_name"] = <cloned_module, real_module>  
		std::tuple<UINT_PTR, UINT_PTR> tpModuleData(pucClonedModule, pucRealModule);
		std::pair<std::string, std::tuple<UINT_PTR, UINT_PTR>> pModuleData(pszModuleName, tpModuleData);

		m_mClonedModules.insert(pModuleData);
	}

	pImageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pucRealModule + reinterpret_cast<PIMAGE_DOS_HEADER>(pucRealModule)->e_lfanew);
	pFunctionAddressToHook = NULL;

	if (pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
	{
		PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
		PDWORD pNamePointers;
		PWORD pOrdinalPointers;
		PDWORD pAddressesPointers;

		pImageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pucRealModule + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		pNamePointers = reinterpret_cast<PDWORD>(pucRealModule + pImageExportDirectory->AddressOfNames);
		pOrdinalPointers = reinterpret_cast<PWORD>(pucRealModule + pImageExportDirectory->AddressOfNameOrdinals);
		pAddressesPointers = reinterpret_cast<PDWORD>(pucRealModule + pImageExportDirectory->AddressOfFunctions);

		// Iterate over all exports and find the address of lpProcName
		for (size_t i = 0; i < pImageExportDirectory->NumberOfNames; ++i, ++pNamePointers, ++pOrdinalPointers)
		{
			LPCSTR lpCurrFunctionName = reinterpret_cast<LPCSTR>(pucRealModule + *pNamePointers);
			if (strcmp(pszProcName.c_str(), lpCurrFunctionName) == 0)
			{
				DWORD dwFuncRVA = pAddressesPointers[*pOrdinalPointers];

				pFunctionAddressToHook = pucRealModule + dwFuncRVA;
				break;

			}
		}

		if (pFunctionAddressToHook == NULL)
		{
			return false;
		}

		bHookSucceed = false;
		uNumberOfBytesOverwritten = 0;
		switch (hhtHookType)
		{
		case SUPERHOOKTYPE_ABSOLUTEJMP:
			bHookSucceed = absolutejmp_hook(pFunctionAddressToHook, pHookFunction, &uNumberOfBytesOverwritten);
			break;

		case SUPERHOOKTYPE_RET:
			break;

		default:
			break;

		}

		// If hook succeed add hook data to m_mFunctionsHookData
		if (bHookSucceed)
		{
			UINT_PTR pClonedFunctionAddress = (pFunctionAddressToHook - pucRealModule) + pucClonedModule;

			// ["function_name"] = <cloned_function_addr, real_function_addr, number_of_bytes_overwritten>  
			std::tuple<UINT_PTR, UINT_PTR, unsigned int> tpFunctionData(pClonedFunctionAddress, pFunctionAddressToHook, uNumberOfBytesOverwritten);
			std::pair<std::string, std::tuple<UINT_PTR, UINT_PTR, unsigned int>> prFunctionData(pszProcName, tpFunctionData);

			m_mFunctionsHookData.insert(prFunctionData);
		}

	}


}

UINT_PTR SuperHook::ClonedFunction(std::string pszProcName)
{

	auto it = this->m_mFunctionsHookData.find(pszProcName);
	if (it != this->m_mFunctionsHookData.end())
	{
		return std::get<0>(it->second);
	}

	return 0;
}

bool SuperHook::absolutejmp_hook(UINT_PTR pFunctionToHook, UINT_PTR pHookFunction, __out unsigned int* uNumberOfBytesOverwritten)
{
	bool bSucceed = true;
	if (uNumberOfBytesOverwritten == NULL)
	{
		return false;
	}

	*uNumberOfBytesOverwritten = 0;

	try
	{
#ifdef _WIN64
		DWORD dwOldProtect;
		VirtualProtect((LPVOID)pFunctionToHook, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		InterlockedExchange8((char*)pFunctionToHook, '\xC3');

		// jmp rax.
		*(char*)(pFunctionToHook + 10) = '\xFF';
		*(char*)(pFunctionToHook + 11) = '\xE0';

		// movabs rax, pMalicousFunction
		*(ULONG_PTR*)(pFunctionToHook + 2) = pHookFunction;
		*(char*)(pFunctionToHook + 1) = '\xB8';
		InterlockedExchange8((char*)pFunctionToHook, '\x48');

		// We now changed the function to run
		// mov rax, pMalicousFunction
		// jmp rax

		VirtualProtect((LPVOID)pFunctionToHook, 12, dwOldProtect, &dwOldProtect);

#elif _WIN32
		DWORD dwOldProtect;
		VirtualProtect((LPVOID)pFunctionToHook, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		InterlockedExchange8((char*)pFunctionToHook, '\xC3');

		// jmp eax.
		*(char*)(pFunctionToHook + 5) = '\xFF';
		*(char*)(pFunctionToHook + 6) = '\xE0';

		// mov eax, pMalicousFunction
		*(ULONG_PTR*)(pFunctionToHook + 1) = pHookFunction;
		InterlockedExchange8((char*)pFunctionToHook, '\xB8');

		// We now changed the function to run
		// mov eax, pMalicousFunction
		// jmp eax

		VirtualProtect((LPVOID)pFunctionToHook, 7, dwOldProtect, &dwOldProtect);

#endif
	}
	catch (const std::exception&)
	{
		bSucceed = false;
	}

	return bSucceed;
}

HMODULE SuperHook::ManualGetModuleByName(std::string pszModuleName)
{
	return GetModuleHandleA(pszModuleName.c_str());
}

UINT_PTR SuperHook::CloneModule(UINT_PTR pucRealModule)
{
	DWORD dwSizeOfImage;
	DWORD dwOldProtect;

	UINT_PTR pucClonedModule;

	SYSTEM_INFO sysInfo;
	

	pucClonedModule = NULL;
	try
	{
		dwSizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(pucRealModule + reinterpret_cast<PIMAGE_DOS_HEADER>(pucRealModule)->e_lfanew)->OptionalHeader.SizeOfImage;

		pucClonedModule = reinterpret_cast<UINT_PTR>(new unsigned char[dwSizeOfImage] {});

		if (!IsWow64())
		{
			for (size_t i = 0; i < dwSizeOfImage; i++)
			{
				reinterpret_cast<unsigned char*>(pucClonedModule)[i] = reinterpret_cast<unsigned char*>(pucRealModule)[i];
			}
		}
		else
		{
			// Look at kernel32.dll under wow64, fking stupid fuck on microsoft
			GetSystemInfo(&sysInfo);
			for (size_t i = 0; i < dwSizeOfImage; i += sysInfo.dwPageSize)
			{
				MEMORY_BASIC_INFORMATION mbi;

				VirtualQuery(reinterpret_cast<unsigned char*>(pucRealModule) + i, &mbi, sizeof(mbi));

				if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)
				{
					for (size_t j = 0; j < sysInfo.dwPageSize; j++)
					{
						reinterpret_cast<unsigned char*>(pucClonedModule)[i + j] = reinterpret_cast<unsigned char*>(pucRealModule)[i + j];
					}
				}
			}

		}
		

		UINT_PTR pucCurrentSection;
		unsigned int uNumberOfSections;
		VirtualProtect(reinterpret_cast<LPVOID>(pucClonedModule), dwSizeOfImage, PAGE_READONLY, &dwOldProtect);

		uNumberOfSections = reinterpret_cast<PIMAGE_NT_HEADERS>(pucRealModule + reinterpret_cast<PIMAGE_DOS_HEADER>(pucRealModule)->e_lfanew)->FileHeader.NumberOfSections;
		pucCurrentSection = reinterpret_cast<UINT_PTR>(IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(pucRealModule + reinterpret_cast<PIMAGE_DOS_HEADER>(pucRealModule)->e_lfanew)));
		for (size_t i = 0; i < uNumberOfSections; i++)
		{
			DWORD dwProtectionFlag = 0;

			dwProtectionFlag = CalculateProtectionFlags(reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Characteristics);

			VirtualProtect(reinterpret_cast<LPVOID>(pucClonedModule + reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->VirtualAddress), reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Misc.VirtualSize, dwProtectionFlag, &dwOldProtect);

		}

		VirtualProtect(reinterpret_cast<LPVOID>(pucClonedModule), dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	}
	catch (const std::exception&)
	{

	}

	return pucClonedModule;
}

