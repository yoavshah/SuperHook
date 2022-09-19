/*
	Created by Yoav Shaharabani (github.com/yoavshah)
	Use with your own risk and care.
	DO NOT USE FOR MALICIOUS PURPOSES!
	FOLLOW ME ON GITHUB AND BUY ME A COFFEE
*/

#pragma once

#include <Windows.h>
#include <map>
#include <string>
#include <vector>



enum SuperHookType {
	SUPERHOOKTYPE_ABSOLUTEJMP,
	SUPERHOOKTYPE_RET

};

class SuperHook {

private:
	bool m_bLoaded;

	// ["function_name"] = <cloned_function_addr, real_function_addr, number_of_bytes_overwritten>  
	std::map < std::string, std::tuple<UINT_PTR, UINT_PTR, unsigned int>> m_mFunctionsHookData;

	// ["module_name"] = <cloned_module, real_module>  
	std::map<std::string, std::tuple<UINT_PTR, UINT_PTR>> m_mClonedModules;

public:
	SuperHook();

	~SuperHook();

	bool HookFunction(std::string pszModuleName, std::string pszProcName, UINT_PTR pHookFunction, SuperHookType hhtHookType);

	UINT_PTR ClonedFunction(std::string pszProcName);

private:

	bool absolutejmp_hook(UINT_PTR pFunctionToHook, UINT_PTR pHookFunction, __out unsigned int* uNumberOfBytesOverwritten);

	HMODULE ManualGetModuleByName(std::string pszModuleName);

	UINT_PTR CloneModule(UINT_PTR pucRealModule);

};