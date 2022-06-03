
# SuperHook

  ## SuperHook is an easy to use and understand framework for hooking any address inside a module loaded to memory (DLL, EXE) that support x64 and x86 architectures.

  ## Usage
  
  * Include SuperHook.hpp to your project.
  * Declare global super_hook variable with your function you want to hook inside decltype, super_hook<decltype(&MessageBoxA)> x;
  * Create a malicous function with the same signature as the function you want to hook.
  * Call the function init inside the global variable you created with the address of the function to hook as parameter.
  * Run one of the hooking functions.
  * You can also remove the hooking using remove_hook function or uninit function.


  ## How does it works
  
  * Given a function to hook this library creates a copy of the module that contains the function.
  * Then it overwrite the real module with the hook (like mov eax, addr; call eax).
  * When ever you need to call the real function, just use super_hook.get_function() and you will get an instance of the unhooked function (inside the cloned module).


  ## Notes
  * Do not try to hook VirtualProtect, it might crash the library.
  * Use with great care on projects, as the whole cloned dll have PAGE_EXECUTE_READWRITE protection.
  * There is a problem with super_hook.remove_hook() using x64 architecture, you can use the hooked function again only if the function was used before the hooking happend and I don't know how to solve this issue.



