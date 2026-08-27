; AsmHostIdt.asm
; private host IDT handlers for VMX-root mode

PUBLIC asm_host_nmi_handler
PUBLIC asm_host_df_handler
PUBLIC asm_host_gp_handler
PUBLIC asm_host_default_handler
EXTERN g_vmxoff_transition_count:DWORD
EXTERN g_vmxoff_nmi_deferred:DWORD


.code _text


; NMI handler — resolves the current vCPU from the immutable HOST_RSP slot.
; VIRTUAL_MACHINE_STATE.host_nmi_pending is deliberately the first member.

asm_host_nmi_handler PROC

    push    rax
    push    rcx
    cmp     dword ptr [g_vmxoff_transition_count], 0
    je      HostNmiVmcs
    lock inc dword ptr [g_vmxoff_nmi_deferred]
    jmp     HostNmiDone

HostNmiVmcs:


    mov     ecx, 06C14h           ; VMCS_HOST_RSP
    vmread  rax, rcx
    jz      HostNmiDone
    jc      HostNmiDone
    mov     rax, qword ptr [rax+8] ; vCPU pointer stored at HOST_RSP+8
    test    rax, rax
    jz      HostNmiDone
    mov     dword ptr [rax], 1

HostNmiDone:
    pop     rcx
    pop     rax
    iretq

asm_host_nmi_handler ENDP


; #DF in host mode = unrecoverable, halt

asm_host_df_handler PROC

    cli
    hlt
    jmp     $

asm_host_df_handler ENDP


; #GP in host mode = bug, halt

asm_host_gp_handler PROC

    cli
    hlt
    jmp     $

asm_host_gp_handler ENDP


; catch-all for unexpected vectors, halt

asm_host_default_handler PROC

    cli
    hlt
    jmp     $

asm_host_default_handler ENDP


END
