                        .586p
                        .model  flat, stdcall
                        option casemap:none

                        .code
ExportBreakpoint        proc    dwSize:dword
                        mov     eax, shellcode_end - shellcode
                        mov     ecx, dwSize
                        mov     dword ptr[ecx], eax
                        mov     eax, offset shellcode
                        ret
ExportBreakpoint        endp

_DATA                   segment
                        assume fs:nothing
shellcode:              push    0
                        pushad
                        call    __delta
__delta:                pop     ebp                  
                        lea     edi, [esp+24h+10h]
                                    
__loop_debugattach:     cmp     dword ptr [ebp+ (trigger - __delta)], 1
                        je      __int3
                        call    dword ptr [ebp+(ntyieldexecution - __delta)]
                        mov     eax, [edi+0b0h] ;context.eax
                        cmp     byte ptr[eax], 0c3h
                        je      __trigger
                        cmp     eax, [ebp+(dbguiremotebreakin - __delta)]
                        jne     __loop_debugattach
__trigger:              mov     eax, 1
                        xchg    [ebp+(trigger - __delta)], eax
                        push    0
                        push    -2
                        call    dword ptr [ebp+(ntterminatethread - __delta)]
                        
__int3:                 mov     edi, [ebp+(ldrinitializethunk - __delta)]
                        lea     esi, [ebp+(__oldbytes - __delta)]
                        mov     ecx, [ebp+(len - __delta)]
                        cld
                        rep     movsb
                        
                        mov     eax, [ebp+(ldrinitializethunk - __delta)]
                        mov     [esp+20h], eax
                        popad
                        
                        int     3                        
                        
                        ret
trigger:                
                        dd      0
__oldbytes:                        
                        db      20h     dup(90h)

len                     dd      ?  
dbguiremotebreakin      dd      ? 
ldrinitializethunk      dd      ?                     
ntyieldexecution        dd      ?                        
ntterminatethread       dd      ?
shellcode_end:                        
_DATA                   ends

                        end