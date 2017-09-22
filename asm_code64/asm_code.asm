                        .code
public ExportBreakpoint        
ExportBreakpoint:
                        mov     dword ptr [rcx], shellcode_end - shellcode
                        mov     rax, offset shellcode
                        ret
                        
                        .data
shellcode:              push    rcx
                        push    rdx
                        push    rbx
                        sub     rsp, 30h
                        mov     rbx, rcx            
__loop_debugattach:     cmp     trigger, 1
                        je      __int3
                        call    ntyieldexecution
                        mov     rax, [rbx+080h] ;context.rcx
                        cmp     byte ptr[rax], 0c3h
                        je      __trigger
                        cmp     rax, dbguiremotebreakin
                        jne     __loop_debugattach
__trigger:              mov     eax, 1
                        xchg    trigger, eax
                        mov     rdx, 0
                        mov     rcx, -2
                        call    ntterminatethread
                        
__int3:                 mov     rdi, ldrinitializethunk
                        lea     rsi, __oldbytes
                        mov     rcx, len
                        cld
                        rep     movsb
                        
                        add     rsp, 30h
                        pop     rbx
                        pop     rdx
                        pop     rcx
                        push    ldrinitializethunk
                        int     3 
                        ret
                                               
trigger                 dd      0
__oldbytes:                        
                        db      20h     dup(90h)

len                     dq      ?  
dbguiremotebreakin      dq      ? 
ldrinitializethunk      dq      ?                     
ntyieldexecution        dq      ?                        
ntterminatethread       dq      ?
shellcode_end:                        
                        end