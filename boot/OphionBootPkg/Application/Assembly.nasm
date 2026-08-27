;------------------------------------------------------------------------------
; Assembly.nasm - VMX intrinsics and the VM-exit stub for OphionBoot.
;
; The stub mirrors the runtime core's AsmVmexitHandler contract:
;   HOST_RSP points 16 bytes below the top of the per-core host stack with
;   the OPB_VCPU pointer stored at HOST_RSP+8. On exit we save volatile and
;   non-volatile GPRs plus XMM0-5/MXCSR, call the C handler, and either
;   VMRESUME (handler returned FALSE) or VMXOFF-return (returned TRUE).
;------------------------------------------------------------------------------

extern ASM_PFX(OpbVmExitHandler)
extern ASM_PFX(OpbSetupCurrentCore)
extern ASM_PFX(OpbVmxEntryFailure)
DEFAULT REL
SECTION .text

global ASM_PFX(AsmEnableVmxAndVmxon)
global ASM_PFX(AsmVmExitStub)
global ASM_PFX(AsmInveptSingleContext)
global ASM_PFX(OpbAsmSaveAndVirtualize)
global ASM_PFX(OpbAsmLaunchResume)
global ASM_PFX(OpbVmread)
global ASM_PFX(OpbVmwrite)


;------------------------------------------------------------------------------
; EFI_STATUS AsmEnableVmxAndVmxon(UINT64 VmxonPhysicalAddress)
;   rcx = physical address of the 4KB VMXON region (revision id written).
;------------------------------------------------------------------------------
ASM_PFX(AsmEnableVmxAndVmxon):
    push    rbx
    sub     rsp, 16
    mov     rbx, rcx
    mov     rax, cr4
    or      rax, 0x2000              ; CR4.VMXE
    mov     cr4, rax
    mov     eax, 0x480               ; IA32_VMX_BASIC
    rdmsr
    mov     [rbx], eax               ; revision identifier
    mov     [rsp], rbx               ; VMXON operand is a pointer to PA
    vmxon   [rsp]
    jnc     .vmxon_ok
    jmp     .vmxon_fail
.vmxon_ok:
    xor     rax, rax                 ; EFI_SUCCESS
    add     rsp, 16
    pop     rbx
    ret
.vmxon_fail:
    mov     rax, 0x800000000000000E  ; EFI_UNSUPPORTED
    add     rsp, 16
    pop     rbx
    ret

;------------------------------------------------------------------------------
; EFI_STATUS AsmInveptSingleContext(UINT64 EptPointer)
;------------------------------------------------------------------------------
ASM_PFX(AsmInveptSingleContext):
    push    rbx
    sub     rsp, 16
    mov     [rsp], rcx               ; INVEPT descriptor: EPTP
    mov     qword [rsp+8], 0
    xor     rcx, rcx
    inc     rcx                      ; type 1 = single-context
    lea     rdx, [rsp]
    invept  rcx, [rdx]
    jnc     .ok
    jmp     .fail
.ok:
    xor     rax, rax
    add     rsp, 16
    pop     rbx
    ret
.fail:
    mov     rax, 0x800000000000000E
    add     rsp, 16
    pop     rbx
    ret

;------------------------------------------------------------------------------
; EFI_STATUS OpbAsmSaveAndVirtualize(UINT32 CoreIndex)
; Save the UEFI caller's complete machine context, ask C to construct the
; VMCS with this frame as GUEST_RSP, then VMLAUNCH. Successful entry resumes
; at OpbAsmLaunchResume and returns to the original UEFI caller non-root.
;------------------------------------------------------------------------------
ASM_PFX(OpbAsmSaveAndVirtualize):
    push    0
    pushfq
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
    push    rbx
    push    rdx
    push    rcx
    push    rax
    sub     rsp, 0x20

    mov     ecx, [rsp + 0x28]        ; saved CoreIndex / original RCX
    mov     rdx, rsp                 ; saved guest frame
    call    ASM_PFX(OpbSetupCurrentCore)
    test    rax, rax
    jnz     .launch_fail

    vmlaunch
    mov     ecx, [rsp + 0x28]
    mov     edx, 2                  ; terminal VM-entry failure
    sub     rsp, 0x28
    call    ASM_PFX(OpbVmxEntryFailure)
    cli
    jmp     $

.launch_fail:
    add     rsp, 0x20
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
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
    popfq
    add     rsp, 8
    ret

ASM_PFX(OpbAsmLaunchResume):
    add     rsp, 0x20
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
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
    popfq
    add     rsp, 8
    ret

;------------------------------------------------------------------------------
; AsmVmExitStub - HOST_RIP target.
;------------------------------------------------------------------------------
ASM_PFX(AsmVmExitStub):
    push    0                        ; alignment padding
    pushfq

    sub     rsp, 0x110
    movaps  [rsp+0x000], xmm0
    movaps  [rsp+0x010], xmm1
    movaps  [rsp+0x020], xmm2
    movaps  [rsp+0x030], xmm3
    movaps  [rsp+0x040], xmm4
    movaps  [rsp+0x050], xmm5
    stmxcsr dword [rsp+0x100]

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
    push    rbp                      ; placeholder for guest RSP
    push    rbx
    push    rdx
    push    rcx
    push    rax
    mov     ecx, 0x681c             ; VMCS_GUEST_RSP
    vmread  rax, rcx
    mov     [rsp+0x20], rax         ; OPB_GUEST_REGS.rsp

    mov     rcx, rsp                 ; OPB_GUEST_REGS*
    mov     rdx, [rsp + 0x1A8]       ; OPB_VCPU* at HOST_RSP+8

    sub     rsp, 0x20                ; shadow space
    call    ASM_PFX(OpbVmExitHandler)
    add     rsp, 0x20
    mov     r11b, al
    mov     rax, [rsp+0x20]          ; OPB_GUEST_REGS.rsp
    mov     ecx, 0x681c
    vmwrite rax, rcx
    jnc     .resume_prepare
    mov     rcx, [rsp + 0x1A8]
    mov     edx, 1
    sub     rsp, 0x28
    call    ASM_PFX(OpbVmxEntryFailure)
.resume_prepare:
    cmp     r11b, 1

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp                      ; discard RSP placeholder
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

    movaps  xmm0, [rsp+0x000]
    movaps  xmm1, [rsp+0x010]
    movaps  xmm2, [rsp+0x020]
    movaps  xmm3, [rsp+0x030]
    movaps  xmm4, [rsp+0x040]
    movaps  xmm5, [rsp+0x050]
    ldmxcsr dword [rsp+0x100]
    add     rsp, 0x110

    popfq
    add     rsp, 8                   ; skip alignment padding

    vmresume
    ; VMRESUME failure is terminal; HOST_RSP has been restored to stack top.
    mov     rcx, [rsp-8]
    mov     edx, 2
    sub     rsp, 0x28
    call    ASM_PFX(OpbVmxEntryFailure)
    cli
.halt:
    hlt
    jmp     .halt

.vmxoff_path:
    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp                      ; discard RSP placeholder
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

    movaps  xmm0, [rsp+0x000]
    movaps  xmm1, [rsp+0x010]
    movaps  xmm2, [rsp+0x020]
    movaps  xmm3, [rsp+0x030]
    movaps  xmm4, [rsp+0x040]
    movaps  xmm5, [rsp+0x050]
    ldmxcsr dword [rsp+0x100]
    add     rsp, 0x110

    popfq
    add     rsp, 8

    vmxoff
    mov     rax, cr4
    and     rax, ~0x2000
    mov     cr4, rax
    ret

;------------------------------------------------------------------------------
; OpbAsmLaunch - build guest state to re-enter at the caller and VMLAUNCH.
; The C bring-up stores the continuation context; this helper only needs a
; naked VMLAUNCH with failure reporting.
;------------------------------------------------------------------------------
global ASM_PFX(OpbAsmVmlaunch)
ASM_PFX(OpbAsmVmlaunch):
    vmlaunch
    mov     rax, 0x800000000000000E  ; EFI_UNSUPPORTED on failure
    ret

global ASM_PFX(AsmVmread64)
ASM_PFX(AsmVmread64):
    vmread  rax, rcx
    ret

global ASM_PFX(AsmVmwrite64)
ASM_PFX(AsmVmwrite64):
    vmwrite  rdx, rcx
    xor     rax, rax
    ret

global ASM_PFX(OpbVmread)
ASM_PFX(OpbVmread):
    vmread  rax, rcx
    jc      .vmread_fail
    mov     [rdx], rax
    xor     rax, rax
    ret
.vmread_fail:
    mov     rax, 0x800000000000000E
    ret

global ASM_PFX(OpbVmwrite)
ASM_PFX(OpbVmwrite):
    vmwrite rdx, rcx
    jnc     .vmwrite_ok
    mov     rax, 0x800000000000000E
    ret
.vmwrite_ok:
    xor     rax, rax
    ret

global ASM_PFX(OpbVmclear)
ASM_PFX(OpbVmclear):
    vmclear [rcx]
    jnc .vmclear_ok
    mov     rax, 0x800000000000000E
    ret
.vmclear_ok:
    xor     rax, rax
    ret

global ASM_PFX(OpbVmptrld)
ASM_PFX(OpbVmptrld):
    vmptrld [rcx]
    jnc .vmptrld_ok
    mov     rax, 0x800000000000000E
    ret
.vmptrld_ok:
    xor     rax, rax
    ret
