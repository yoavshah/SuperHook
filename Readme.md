
# SuperHook

  ## SuperHook is a lightweight easy to use and understand library for hooking any address inside a module loaded to memory (DLL, EXE) that support x64 and x86 architectures.

  ## Usage
  
  * Add SuperHook.cpp to your project and include SuperHook.h.
  * Declare global SuperHookModule variable for your module;
  * For each function you want to hook, create a global SuperHookFunction for it
  * Create a malicous function with the same signature as the function you want to hook.
  * Set the hook


  ## How does it works
  
  * Given a module to SuperHookModule, it will create a copy for the module.
  * Given a function and a SuperHookModule to SuperHookFunction it will hook the function and set the original function so you will be able to use it later.
  * When ever you need to call the real function, just use SuperHookFunction.GetOriginalFunction() and you will get an instance of the unhooked function (inside the cloned module).


  ## Notes

  * Do not try to hook VirtualProtect, it might crash the library.
  * Use with great care on projects, as the whole cloned dll have PAGE_EXECUTE_READWRITE protection.


  ## TODO

  * Let the user send the WinApi function so the library will not use any imports
  * Add more hook methods
  * There are race conditions on the hook method ABSOLUTE_JMP



