/*
	Created by Yoav Shaharabani (github.com/yoavshah)
	Use with your own risk and care.
	DO NOT USE FOR MALICIOUS PURPOSES!
	FOLLOW ME ON GITHUB AND BUY ME A COFFEE
*/

#pragma once

#include <Windows.h>




enum SuperHookType {
	SUPERHOOKTYPE_ABSOLUTEJMP,
	SUPERHOOKTYPE_RET

};

class SuperHookModule
{
private:
	UINT_PTR m_pModule;
	UINT_PTR m_pCloneModule;
	unsigned int m_uCloneModuleSize;

public:
	SuperHookModule(UINT_PTR pModuleBase);

	~SuperHookModule();


	UINT_PTR GetOriginalModule();
	UINT_PTR GetClonedModule();

private:
	bool CloneModule();

};


class SuperHookFunction
{
private:
	SuperHookModule* m_pSuperHookModule;
	UINT_PTR m_pHookedFunctionPointer;
	UINT_PTR m_pClonedFunctionPointer;
	UINT_PTR m_pMaliciousFunctionPointer;
	

	bool m_IsHooked;
	unsigned int m_uNumberOfBytesChanged;


public:
	SuperHookFunction(SuperHookModule* pSuperHookModule, UINT_PTR pHookedFunctionPointer, UINT_PTR pMaliciousFunctionPointer);

	~SuperHookFunction();

	bool SetHook(SuperHookType hhtHookType);

	bool UnHook();
	
	bool IsHooked();

	UINT_PTR GetOriginalFunction();
};




