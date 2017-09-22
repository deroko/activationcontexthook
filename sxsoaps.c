#include        "defs.h"

BOOL    WINAPI  DllMain(__in HINSTANCE hInstance, __in DWORD fdwReason, __in PVOID lpReserved){
        if (fdwReason == DLL_PROCESS_ATTACH){
                MessageBox(0, L"dll hooked...", L"oki", 0);        
        }        
        return TRUE;
}