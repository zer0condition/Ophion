;------------------------------------------------------------------------------
; LaunchPad.nasm - per-core launch landing pad and descriptor helpers.
;------------------------------------------------------------------------------

DEFAULT REL
SECTION .text

extern ASM_PFX(OpbLaunchContinueReturn)

global ASM_PFX(OpbGetLaunchRip)
global ASM_PFX(OpbGetLaunchRsp)
global ASM_PFX(OpbSetHostStackTop)
global ASM_PFX(OpbGdtSetTr)
global ASM_PFX(OpbGdtReadTrBase)
global ASM_PFX(OpbLaunchContinue)
global ASM_PFX(OpbAsmSgdt)
global ASM_PFX(OpbAsmSidt)
global ASM_PFX(OpbAsmReadRflags)
global ASM_PFX(OpbAsmReadRsp)


ASM_PFX(OpbAsmSgdt):
    sgdt    [rcx]
    ret

ASM_PFX(OpbAsmSidt):
    sidt    [rcx]
    ret

ASM_PFX(OpbAsmReadRflags):
    pushfq
    pop     rax
    ret
ASM_PFX(OpbAsmReadRsp):
    mov     rax, rsp
    ret

ASM_PFX(OpbGdtSetTr):
    ; rcx = selector
    ltr     cx
    ret

ASM_PFX(OpbGdtReadTrBase):
    ; rcx = out pointer to UINT64 TR base
    push    rbx
    push    rdi
    sub     rsp, 16
    mov     rdi, rcx
    str     ax
    and     ax, 0xFFF8
    sgdt    [rsp]
    mov     rbx, [rsp + 2]           ; packed GDTR base at offset 2
    movzx   ecx, ax

    movzx   eax, word [rbx + rcx + 2] ; base 0..15
    movzx   edx, byte [rbx + rcx + 4] ; base 16..23
    shl     rdx, 16
    or      rax, rdx
    movzx   edx, byte [rbx + rcx + 7] ; base 24..31
    shl     rdx, 24
    or      rax, rdx
    mov     edx, [rbx + rcx + 8]      ; base 32..63
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi], rax

    add     rsp, 16
    pop     rdi
    pop     rbx
    ret

ASM_PFX(OpbGetLaunchRip):
    lea     rax, [rel ASM_PFX(OpbLaunchContinue)]
    ret

ASM_PFX(OpbGetLaunchRsp):
    mov     rax, rsp
    add     rax, 8
    ret

ASM_PFX(OpbSetHostStackTop):
    ret

;------------------------------------------------------------------------------
; OpbLaunchContinue - guest-mode landing pad. VMLAUNCH enters here with the
; captured RSP so the OpbVirtualizeCurrentCore call frame unwinds naturally
; and the caller continues execution non-root.
;------------------------------------------------------------------------------
ASM_PFX(OpbLaunchContinue):
    xor     rax, rax
    ret
