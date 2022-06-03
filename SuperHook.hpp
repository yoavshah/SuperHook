#pragma once
#include <Windows.h>


template <typename T> class super_hook {

private:
	ULONG_PTR pFunctionToHook;
	ULONG_PTR pFunctionClone;
	ULONG_PTR pModuleToHook;
	ULONG_PTR pModuleClone;

	struct HookData
	{
		bool class_initilized;
		bool hook_exists;
		unsigned long bytes_overwritten;
	} sHookData;
		

public:
	super_hook()
	{
		this->sHookData.class_initilized = false;
		this->sHookData.hook_exists = false;
		this->sHookData.bytes_overwritten = 0;
	}

	bool init(ULONG_PTR pFunctionToHook)
	{
		ULONG_PTR pIterativeAddress; 
		DWORD dwSizeOfClonedModule, dwLastProtect;


		this->pFunctionToHook = pFunctionToHook;

		this->sHookData.hook_exists = false;
		this->sHookData.bytes_overwritten = 0;
		this->sHookData.class_initilized = true;

		/*
			STEP 0
			This code was taken from https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c at STEP 0 
			
			Search for the base address of the module that contains the function we want to hook.
		*/
		pIterativeAddress = pFunctionToHook;
		while (TRUE)
		{
			if (((PIMAGE_DOS_HEADER)pIterativeAddress)->e_magic == IMAGE_DOS_SIGNATURE)
			{
				ULONG_PTR pImageNtHeaders = ((PIMAGE_DOS_HEADER)pIterativeAddress)->e_lfanew;

				// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
				// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
				if (pImageNtHeaders >= sizeof(IMAGE_DOS_HEADER) && pImageNtHeaders < 1024)
				{
					pImageNtHeaders = pImageNtHeaders + pIterativeAddress;

					// break if we have found a valid MZ/PE header
					if (((PIMAGE_NT_HEADERS)pImageNtHeaders)->Signature == IMAGE_NT_SIGNATURE)
						break;
				}
			}
			pIterativeAddress--;
		}

		this->pModuleToHook = pIterativeAddress;



		/*
			STEP 1

			- Find the size of the module using _IMAGE_OPTIONAL_HEADER.SizeOfImage.
			- Allocate memory with this size.
			- Change the memory protect attribute to PAGE_EXECUTE_READWRITE.
			- Copy the module to the newly allocated memory.
			- Find the function to hook inside the clone module and save its address.
		*/

		// Find the module size.
		dwSizeOfClonedModule = ((PIMAGE_NT_HEADERS)(this->pModuleToHook + ((PIMAGE_DOS_HEADER)this->pModuleToHook)->e_lfanew))->OptionalHeader.SizeOfImage;

		// Allocate memory with this size.
		// TODO check if HeapAlloc failed.
		this->pModuleClone = (ULONG_PTR)HeapAlloc(GetProcessHeap(), 0, dwSizeOfClonedModule);
		
		// Change the memory protect attribute to PAGE_EXECUTE_READWRITE.
		VirtualProtect((LPVOID)this->pModuleClone, dwSizeOfClonedModule, PAGE_EXECUTE_READWRITE, &dwLastProtect);
		
		// Copy the module to the newly allocated memory.
		CopyMemory((LPVOID)this->pModuleClone, (LPVOID)this->pModuleToHook, dwSizeOfClonedModule);
		
		// Find the function to hook inside the clone module and save its address.
		this->pFunctionClone = this->pModuleClone + this->pFunctionToHook - this->pModuleToHook;


		/*
			STEP 2
			Now everything is ready to run.

			You have plenty of functions with different code to hook the function u want.
		*/
			
		return true;
	}

	/* This function returnes the real function that got hooked. */
	T get_function()
	{
		if (this->sHookData.class_initilized)
		{
			return static_cast<T>((LPVOID)this->pFunctionClone);
		}
		return static_cast<T>(NULL);
	}

	/* Performe absolute jmp hook on the function to hook. */
	void absolutejmp_hook(ULONG_PTR pMalicousFunction)
	{
		if (this->sHookData.class_initilized && !this->sHookData.hook_exists)
		{
#ifdef _WIN64
			DWORD dwOldProtect;
			VirtualProtect((LPVOID)this->pFunctionToHook, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			InterlockedExchange8((char*)this->pFunctionToHook, '\xC3');

			// jmp rax.
			*(char*)(this->pFunctionToHook + 10) = '\xFF';
			*(char*)(this->pFunctionToHook + 11) = '\xE0';

			// movabs rax, pMalicousFunction
			*(ULONG_PTR*)(this->pFunctionToHook + 2) = pMalicousFunction;
			*(char*)(this->pFunctionToHook + 1) = '\xB8';
			InterlockedExchange8((char*)this->pFunctionToHook, '\x48');

			// We now changed the function to run
			// mov rax, pMalicousFunction
			// jmp rax

			VirtualProtect((LPVOID)this->pFunctionToHook, 12, dwOldProtect, &dwOldProtect);
			this->sHookData.hook_exists = true;
			this->sHookData.bytes_overwritten = 12;


#elif _WIN32
			DWORD dwOldProtect;
			VirtualProtect((LPVOID)this->pFunctionToHook, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			InterlockedExchange8((char*)this->pFunctionToHook, '\xC3');

			// jmp eax.
			*(char*)(this->pFunctionToHook + 5) = '\xFF';
			*(char*)(this->pFunctionToHook + 6) = '\xE0';

			// mov eax, pMalicousFunction
			*(ULONG_PTR*)(this->pFunctionToHook + 1) = pMalicousFunction;
			InterlockedExchange8((char*)this->pFunctionToHook, '\xB8');

			// We now changed the function to run
			// mov eax, pMalicousFunction
			// jmp eax

			VirtualProtect((LPVOID)this->pFunctionToHook, 7, dwOldProtect, &dwOldProtect);

			this->sHookData.hook_exists = true;
			this->sHookData.bytes_overwritten = 7;
#endif
		}
	}

	void ret_hook(ULONG_PTR pMalicousFunction)
	{
		if (this->sHookData.class_initilized && !this->sHookData.hook_exists)
		{
#ifdef _WIN64
			DWORD dwOldProtect;
			VirtualProtect((LPVOID)this->pFunctionToHook, 20, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			InterlockedExchange8((char*)this->pFunctionToHook, '\xC3');

			// ret.
			*(char*)(this->pFunctionToHook + 19) = '\xC3';

			// mov DWORD PTR[rsp + 0x4], <HighPart pMalicousFunction>
			*(char*)(this->pFunctionToHook + 11) = '\xc7';
			*(char*)(this->pFunctionToHook + 12) = '\x44';
			*(char*)(this->pFunctionToHook + 13) = '\x24';
			*(char*)(this->pFunctionToHook + 14) = '\x04';
			*(DWORD*)(this->pFunctionToHook + 15) = (DWORD)(pMalicousFunction >> 32);

			// DWORD PTR[rsp], <LowPart pMalicousFunction>  c7 04 24 ef cd ab 89
			*(char*)(this->pFunctionToHook + 4) = '\xc7';
			*(char*)(this->pFunctionToHook + 5) = '\x04';
			*(char*)(this->pFunctionToHook + 6) = '\x24';
			*(DWORD*)(this->pFunctionToHook + 7) = (DWORD)(pMalicousFunction & 0xFFFFFFFF);

			// sub rsp, 0x8
			*(char*)(this->pFunctionToHook + 1) = '\x83';
			*(char*)(this->pFunctionToHook + 2) = '\xec';
			*(char*)(this->pFunctionToHook + 3) = '\x08';
			InterlockedExchange8((char*)this->pFunctionToHook, '\x48');

			// We now changed the function to run
			//  sub rsp, 0x8
			//  DWORD PTR[rsp], <LowPart pMalicousFunction>
			//  mov DWORD PTR[rsp + 0x4], <HighPart pMalicousFunction>
			//  ret

			VirtualProtect((LPVOID)this->pFunctionToHook, 20, dwOldProtect, &dwOldProtect);
			this->sHookData.hook_exists = true;
			this->sHookData.bytes_overwritten = 20;


#elif _WIN32
			DWORD dwOldProtect;
			VirtualProtect((LPVOID)this->pFunctionToHook, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			InterlockedExchange8((char*)this->pFunctionToHook, '\xC3');

			// ret.
			*(char*)(this->pFunctionToHook + 5) = '\xC3';

			// push pMalicousFunction
			*(ULONG_PTR*)(this->pFunctionToHook + 1) = pMalicousFunction;
			InterlockedExchange8((char*)this->pFunctionToHook, '\x68');

			// We now changed the function to run
			// push pMalicousFunction
			// ret

			VirtualProtect((LPVOID)this->pFunctionToHook, 6, dwOldProtect, &dwOldProtect);

			this->sHookData.hook_exists = true;
			this->sHookData.bytes_overwritten = 6;
#endif
		}
	}

	/* Remove placed hook. */
	void remove_hook()
	{
		DWORD dwOldProtect;

		if (this->sHookData.class_initilized && this->sHookData.hook_exists)
		{
			VirtualProtect((LPVOID)this->pFunctionToHook, this->sHookData.bytes_overwritten, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			InterlockedExchange8((char*)this->pFunctionToHook, '\xC3');

			for (size_t i = this->sHookData.bytes_overwritten - 1; i >= 1; i--)
			{
				*(char*)(this->pFunctionToHook + i) = *(char*)(this->pFunctionClone + i);
			}

			InterlockedExchange8((char*)this->pFunctionToHook, *(char*)this->pFunctionClone);

			VirtualProtect((LPVOID)this->pFunctionToHook, this->sHookData.bytes_overwritten, dwOldProtect, &dwOldProtect);

			this->sHookData.hook_exists = false;
			this->sHookData.bytes_overwritten = 0;
		}
	}

	/* Remove placed hook and free module clone from memory. */
	void uninit()
	{
		if (this->sHookData.class_initilized)
		{
			remove_hook();
			this->pRealFunction = 0;
			this->pClonedFunction = 0;
			this->pRealModule = 0;

			this->dwSizeOfClonedModule = 0;
			this->sHookData.hook_exists = false;
			this->sHookData.bytes_overwritten = 0;

			HeapFree(GetProcessHeap(), 0, (LPVOID)this->pClonedModule);
			this->pClonedModule = 0;

			this->sHookData.class_initilized = false;
		}
	}

	~super_hook()
	{ 
		remove_hook();		
		HeapFree(GetProcessHeap(), 0, (LPVOID)this->pModuleClone);
	}

};

