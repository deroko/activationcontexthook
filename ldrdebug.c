#include        "defs.h"

PVOID   ExportBreakpoint(__out DWORD *dwSize);

VOID    InjectLdrBreak(__in HANDLE hProcess, __in HANDLE hThread){
        ULONG_PTR               pLdrInitializeThunk;
        ULONG_PTR               pNtYieldExecution;
        ULONG_PTR               pNtTerminateThread;
        ULONG_PTR               pDbgUiRemoteBreakin;
        PVOID                   lpRemoteBuffer;
        
        PVOID                   lpBreakpoint;
        DWORD                   dwBreakpoint;
        
        ULONG                   len;
        DWORD                   dwOldProt;
        

        pLdrInitializeThunk = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrInitializeThunk");
        pNtYieldExecution   = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtYieldExecution");
        pNtTerminateThread  = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtTerminateThread");
        pDbgUiRemoteBreakin = (ULONG_PTR)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "DbgUiRemoteBreakin");

                      
        len  = 32;
        
        lpBreakpoint = ExportBreakpoint(&dwBreakpoint); 
        
        *(ULONG_PTR *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 1) = pNtTerminateThread;
        *(ULONG_PTR *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 2) = pNtYieldExecution; 
        *(ULONG_PTR *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 3) = pLdrInitializeThunk;
        *(ULONG_PTR *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 4) = pDbgUiRemoteBreakin;
        *(ULONG_PTR *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 5) = len;

        memcpy((void *)((ULONG_PTR)lpBreakpoint + dwBreakpoint - sizeof(ULONG_PTR) * 5 - 32), (void *)pLdrInitializeThunk, len);

        lpRemoteBuffer = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, lpRemoteBuffer, lpBreakpoint, dwBreakpoint, 0);

        #ifdef _WIN64
        WriteProcessMemory(hProcess, (void *)pLdrInitializeThunk, "\x48\xb8", 2, 0);
        WriteProcessMemory(hProcess, (void *)(pLdrInitializeThunk+2), &lpRemoteBuffer, 8, 0);
        WriteProcessMemory(hProcess, (void *)(pLdrInitializeThunk+10), "\xff\xe0", 2, 0);
        #else
        WriteProcessMemory(hProcess, (void *)pLdrInitializeThunk, "\x68", 1, 0);
        WriteProcessMemory(hProcess, (void *)(pLdrInitializeThunk+1), &lpRemoteBuffer, 4, 0);
        WriteProcessMemory(hProcess, (void *)(pLdrInitializeThunk+5), "\xc3", 1, 0); 
        #endif
        VirtualProtectEx(hProcess, (void *)pLdrInitializeThunk, len, PAGE_EXECUTE_READWRITE, &dwOldProt);
        
        
        
        
        
}