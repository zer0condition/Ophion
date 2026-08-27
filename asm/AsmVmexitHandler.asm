; asm_vmexit_handler.asm
; vm-exit entry point -- saves all xmm + gprs, calls c handler, restores

PUBLIC asm_vmexit_handler

EXTERN vmexit_handler:PROC
EXTERN vmx_vmresume:PROC

.code _text

; asm_vmexit_handler
;
; this is HOST_RIP -- the cpu jumps here on every vm-exit.
;
; stack layout after all saves (from rsp upward):
;   [rsp + 0x000] rax (GUEST_REGS starts here)
;   [rsp + 0x008] rcx
;   ...
;   [rsp + 0x078] r15
;   [rsp + 0x080] xmm0..xmm5 + mxcsr (0x110 bytes)
;   [rsp + 0x190] rflags (pushfq)
;   [rsp + 0x198] padding (push 0)
;   [rsp + 0x1A0] <-- original HOST_RSP
;   [rsp + 0x1A8] vcpu pointer (stored at HOST_RSP - 8 by vmx_setup_vmcs)
;
; offsets:
;   16 gpr pushes = 0x80
;   xmm area = 0x110
;   pushfq = 0x08
;   push 0 = 0x08
;   total = 0x1A0 from rsp to original HOST_RSP
;   vcpu = rsp + 0x1A0 + 0x08 = rsp + 0x1A8

asm_vmexit_handler PROC

    push    0                   ; alignment padding

    pushfq

    ; save xmm registers (6 volatile + mxcsr = 0x110 bytes)
    sub     rsp, 0110h

    movaps  xmmword ptr [rsp+000h], xmm0
    movaps  xmmword ptr [rsp+010h], xmm1
    movaps  xmmword ptr [rsp+020h], xmm2
    movaps  xmmword ptr [rsp+030h], xmm3
    movaps  xmmword ptr [rsp+040h], xmm4
    movaps  xmmword ptr [rsp+050h], xmm5
    stmxcsr dword ptr   [rsp+100h]

    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rbp             ; placeholder for rsp (read from vmcs later)
    push    rbx
    push    rdx
    push    rcx
    push    rax

    mov     rcx, rsp                ; arg1: PGUEST_REGS
    mov     rdx, [rsp + 01A8h]      ; arg2: vcpu pointer (from vmm stack)

    sub     rsp, 020h               ; shadow space (x64 abi)
    call    vmexit_handler
    add     rsp, 020h

    ; check return value: TRUE = vmxoff, FALSE = vmresume
    cmp     al, 1
    je      VmxoffPath

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp             ; discard rsp placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    movaps  xmm0, xmmword ptr [rsp+000h]
    movaps  xmm1, xmmword ptr [rsp+010h]
    movaps  xmm2, xmmword ptr [rsp+020h]
    movaps  xmm3, xmmword ptr [rsp+030h]
    movaps  xmm4, xmmword ptr [rsp+040h]
    movaps  xmm5, xmmword ptr [rsp+050h]
    ldmxcsr dword ptr   [rsp+100h]

    add     rsp, 0110h

    popfq

    ; skip alignment padding (push 0)
    add     rsp, 08h

    jmp     vmx_vmresume

asm_vmexit_handler ENDP

; vmxoff path -- hypervisor shutting down, restore and return to guest

VmxoffPath PROC

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp             ; discard rsp placeholder
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    movaps  xmm0, xmmword ptr [rsp+000h]
    movaps  xmm1, xmmword ptr [rsp+010h]
    movaps  xmm2, xmmword ptr [rsp+020h]
    movaps  xmm3, xmmword ptr [rsp+030h]
    movaps  xmm4, xmmword ptr [rsp+040h]
    movaps  xmm5, xmmword ptr [rsp+050h]
    ldmxcsr dword ptr [rsp+100h]
    add     rsp, 0110h

    ; vmexit_leave_vmx replaced this slot with guest RFLAGS.
    popfq
    add     rsp, 08h

    ; Return stack/RIP were prepared before VMXOFF. This preserves every GPR.
    mov     rsp, [rsp]
    ret

VmxoffPath ENDP


END
