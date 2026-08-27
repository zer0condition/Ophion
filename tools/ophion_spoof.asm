;
; UINT64 ophion_asm_spoof(void *fn, void *gadget, UINT64 a0, UINT64 a1)
;   rcx=fn  rdx=gadget (ntdll `jmp rbx`)  r8=a0  r9=a1
;
; After `fn` returns, RIP lands on gadget; gadget does `jmp rbx` into restore.
; CaptureStackBackTrace / R5AC see only ntdll between caller and fn.
;

PUBLIC ophion_asm_spoof

_TEXT SEGMENT


ophion_asm_spoof PROC FRAME
    push    rbx                 ; preserve nonvolatile RBX
    .pushreg rbx
    sub     rsp, 20h            ; target's required shadow space
    .allocstack 20h
    .endprolog
    mov     rax, rcx            ; fn
    mov     r11, rdx            ; ntdll `jmp rbx` gadget
    mov     rcx, r8             ; a0
    mov     rdx, r9             ; a1
    lea     rbx, restore
    push    r11                 ; fake target return address
    jmp     rax

restore:
    add     rsp, 20h
    pop     rbx
    ret
ophion_asm_spoof ENDP

_TEXT ENDS
END
