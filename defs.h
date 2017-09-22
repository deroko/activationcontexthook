#define         _CRT_SECURE_NO_WARNINGS
#include        <windows.h>
#include        <stdio.h>
#include        <Objbase.h>
#include        <Commctrl.h>
#include        <mshtml.h>
#include        <strsafe.h>
#include        <winternl.h>

#include        "sxstypes.h"

#include "pshpack4.h"

#define ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_TYPE_SUPPORTED_OS     1
#define ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_TYPE_MITIGATION       2

typedef struct ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_ENTRY{
        GUID    Guid;
        ULONG   Type;
}ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_ENTRY, *PACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_ENTRY;

typedef struct ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_INFO{
        ULONG   ElementCount;
        ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_ENTRY Entry[];
}ACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_INFO, *PACTIVATION_CONTEXT_DATA_APPLICATION_COMPATIBILITY_INFO;
#include "poppack.h"
        
typedef NTSTATUS (NTAPI *RTLHASHUNICODESTRING)(
  PUNICODE_STRING String,
  BOOLEAN          CaseInSensitive,
  ULONG            HashAlgorithm,
  PULONG           HashValue
);
//VOID    RtlInitUnicodeString(__in PUNICODE_STRING pUnicodeString, __in WCHAR *wsUnicodeString);        

#define HASH_STRING_ALGORITHM_DEFAULT   (0)
#define HASH_STRING_ALGORITHM_X65599    (1)
#define HASH_STRING_ALGORITHM_INVALID   (0xffffffff)

NTSTATUS NTAPI NtUnmapViewOfSection(
  __in     HANDLE ProcessHandle,
  __in     PVOID  BaseAddress
);

NTSTATUS NTAPI NtQueryInformationProcess(
  _In_      HANDLE           ProcessHandle,
  _In_      PROCESSINFOCLASS ProcessInformationClass,
  _Out_     PVOID            ProcessInformation,
  _In_      ULONG            ProcessInformationLength,
  _Out_opt_ PULONG           ReturnLength
);

VOID    InjectLdrBreak(__in HANDLE hProcess, __in HANDLE hThread);


