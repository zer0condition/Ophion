; asmVmxIntrinsics.asm
; INVEPT and INVVPID instruction wrappers

PUBLIC asm_invept
PUBLIC asm_invvpid
PUBLIC asm_vmxoff_checked


.code _text

; asm_invept(UINT32 type /*ecx*/, PVOID descriptor /*rdx*/)
; returns 0 on success, 1 on failure

asm_invept PROC
    invept  rcx, oword ptr [rdx]
    jz      InveptFailure       ; ZF=1 means failure (VMfailValid)
    jc      InveptFailure       ; CF=1 means failure (VMfailInvalid)

    xor     rax, rax            ; success
    ret

InveptFailure:
    mov     rax, 1
    ret
asm_invept ENDP

; asm_invvpid(UINT32 type /*ecx*/, PVOID descriptor /*rdx*/)
; returns 0 on success, 1 on failure

asm_invvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz      InvvpidFailure
    jc      InvvpidFailure

    xor     rax, rax
    ret

InvvpidFailure:
    mov     rax, 1
    ret
asm_invvpid ENDP

; asm_vmxoff_checked()
; returns 0 after successful VMXOFF, 1 on VMfailValid/Invalid
asm_vmxoff_checked PROC
    vmxoff
    jz      VmxoffFailure
    jc      VmxoffFailure
    xor     rax, rax
    ret

VmxoffFailure:
    mov     rax, 1
    ret
asm_vmxoff_checked ENDP


END
