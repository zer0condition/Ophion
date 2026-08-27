/*
*   protect.c - per-CR3 + RIP-based EPT split-view
*
*   Owner CR3, secret pages: execute-only (R=0 W=0 X=1) on the real PFN.
*   Other CR3s: dummy page (R=1 W=0 X=0).
*
*   A data read/write of a secret GPA VMEXITs.  If guest RIP is inside
*   the secret image or a registered whitelist range (ntdll/game), we
*   grant R for one instruction via MTF.  If RIP is elsewhere (EAC.sys
*   after KeStackAttachProcess, BEDaisy, Ricochet) the access is
*   satisfied from the dummy page for that instruction.
*
*   That closes kernel-attach reads of internal cheat pages.
*/

#include "hv.h"

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef STEALTH_PROTECT


#define STEALTH_PROTECT 1
#endif

#if STEALTH_PROTECT

#define HV_PROTECT_MAX_PAGES      512
#define HV_PROTECT_MAX_OWNERS     8
#define HV_PROTECT_MAX_WHITELIST  32
#define HV_PROTECT_MAX_MDLS       32
#define HV_PROTECT_MAX_MTF_PAGES  16
typedef struct _HV_PROTECT_PAGE {
    UINT64 gpa;
    UINT64 gva;
    UINT64 real_pfn;
    UINT32 owner;
    UINT32 reserved;
} HV_PROTECT_PAGE;
typedef struct _HV_PROTECT_OWNER {
    UINT64 kernel_cr3;
    UINT64 user_cr3;
    PEPROCESS process;
    PMDL mdl;
    UINT32 page_begin;
    UINT32 page_count;
    BOOLEAN active;
    UINT8 reserved[3];
} HV_PROTECT_OWNER;

typedef struct _HV_PROTECT_WL {
    UINT32 owner;
    UINT32 reserved;
    UINT64 gva;
    UINT64 end;
} HV_PROTECT_WL;

static HV_PROTECT_PAGE  g_prot_pages[HV_PROTECT_MAX_PAGES];
static UINT32           g_prot_page_count;
static HV_PROTECT_OWNER g_prot_owners[HV_PROTECT_MAX_OWNERS];
static UINT32           g_prot_owner_count;
static HV_PROTECT_WL    g_prot_wl[HV_PROTECT_MAX_WHITELIST];
static UINT32           g_prot_wl_count;
static PVOID            g_prot_dummy_va;
static UINT64           g_prot_dummy_pfn;
static BOOLEAN          g_prot_ready;
static KSPIN_LOCK       g_prot_lock;
static FAST_MUTEX       g_prot_registration_mutex;
static BOOLEAN          g_prot_notify_registered;
static UINT64           g_prot_mtf_gpa[MAX_PROCESSORS][HV_PROTECT_MAX_MTF_PAGES];
static UINT8            g_prot_mtf_zero[MAX_PROCESSORS][HV_PROTECT_MAX_MTF_PAGES];
static UINT8            g_prot_mtf_count[MAX_PROCESSORS];
static UINT64
prot_cr3_key(UINT64 cr3)
{
    return cr3 & ~0xFFFULL;
}
static BOOLEAN
prot_owner_matches(UINT32 owner, UINT64 cr3_key)
{
    if (owner >= g_prot_owner_count ||
        !g_prot_owners[owner].active)
        return FALSE;
    return g_prot_owners[owner].kernel_cr3 == cr3_key ||
           g_prot_owners[owner].user_cr3 == cr3_key;
}
static BOOLEAN
prot_owner_of(UINT64 cr3_key, UINT32 * owner_out)
{
    UINT32 i;
    for (i = 0; i < g_prot_owner_count; i++)
    {
        if (prot_owner_matches(i, cr3_key))
        {
            if (owner_out)
                *owner_out = i;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
protect_requires_cr3_exiting(VOID)
{
    UINT32 owner;

    if (!g_prot_ready)
        return FALSE;

    MemoryBarrier();
    for (owner = 0; owner < g_prot_owner_count; owner++)
    {
        if (g_prot_owners[owner].active)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN
prot_set_leaf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 gpa, UINT64 pfn,
              BOOLEAN read, BOOLEAN write, BOOLEAN exec)
{
    PEPT_PML1_ENTRY leaf;
    EPT_PML1_ENTRY  next;

    if (!vcpu || !vcpu->ept_page_table || !gpa)
        return FALSE;
    /*
    * Every protected leaf is pre-split before policy publication.  VMX-root
    * permission paths must never allocate or invoke Windows memory APIs.
    */
    leaf = ept_get_pml1(vcpu->ept_page_table, gpa);
    if (!leaf)
        return FALSE;

    next = *leaf;
    next.PageFrameNumber = pfn;
    next.ReadAccess      = read ? 1 : 0;
    next.WriteAccess     = write ? 1 : 0;
    next.ExecuteAccess   = exec ? 1 : 0;
    InterlockedExchange64(
        (volatile LONG64 *)&leaf->AsUInt,
        (LONG64)next.AsUInt);
    return TRUE;
}

static BOOLEAN
prot_apply_vcpu(VIRTUAL_MACHINE_STATE * vcpu, BOOLEAN owner_view,
                UINT32 begin, UINT32 count)
{
    UINT32 i;
    UINT32 end = begin + count;

    if (end > g_prot_page_count)
        end = g_prot_page_count;
    for (i = begin; i < end; i++)
    {
        BOOLEAN ok;
        if (owner_view)
            ok = prot_set_leaf(vcpu, g_prot_pages[i].gpa,
                               g_prot_pages[i].real_pfn,
                               FALSE, FALSE, TRUE);
        else
            ok = prot_set_leaf(vcpu, g_prot_pages[i].gpa,
                               g_prot_dummy_pfn + i,
                               TRUE, TRUE, FALSE);
        if (!ok)
            return FALSE;
    }
    return TRUE;
}



static BOOLEAN
prot_read_phys_u64(UINT64 pa, UINT64 * value)
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0;

    if (!value)
        return FALSE;
    source.PhysicalAddress.QuadPart = pa;
    return NT_SUCCESS(MmCopyMemory(
               value, source, sizeof(*value),
               MM_COPY_MEMORY_PHYSICAL, &copied)) &&
           copied == sizeof(*value);
}

static UINT64
prot_translate(UINT64 cr3, UINT64 gva)
{
    UINT64 pml4e, pdpe, pde, pte;
    UINT64 table = prot_cr3_key(cr3);

    if (!prot_read_phys_u64(
            table + 8 * ((gva >> 39) & 0x1FF), &pml4e) ||
        !(pml4e & 1))
        return 0;
    if (!prot_read_phys_u64(
            (pml4e & 0x000FFFFFFFFFF000ULL) +
            8 * ((gva >> 30) & 0x1FF), &pdpe) ||
        !(pdpe & 1))
        return 0;
    if (pdpe & 0x80)
        return (pdpe & 0x000FFFFFC0000000ULL) |
               (gva & 0x3FFFFFFFULL);
    if (!prot_read_phys_u64(
            (pdpe & 0x000FFFFFFFFFF000ULL) +
            8 * ((gva >> 21) & 0x1FF), &pde) ||
        !(pde & 1))
        return 0;
    if (pde & 0x80)
        return (pde & 0x000FFFFFFFE00000ULL) |
               (gva & 0x1FFFFFULL);
    if (!prot_read_phys_u64(
            (pde & 0x000FFFFFFFFFF000ULL) +
            8 * ((gva >> 12) & 0x1FF), &pte) ||
        !(pte & 1))
        return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) |
           (gva & 0xFFFULL);
}

static UINT64
prot_find_user_cr3(
    UINT64 kernel_cr3,
    const HV_PROTECT_PAGE * pages,
    UINT32 count)
{
    PUCHAR process = (PUCHAR)PsGetCurrentProcess();
    UINT32 offset;

    if (!process || !pages || !count)
        return kernel_cr3;

    /*
    * Locate a second CR3 root in the opaque EPROCESS/KPROCESS prefix by
    * behavior, not a build-pinned offset: every protected VA must resolve
    * to the same MDL PFN under the candidate root.
    */
    for (offset = 0; offset + sizeof(UINT64) <= 0x500;
         offset += sizeof(UINT64))
    {
        UINT64 candidate = *(UNALIGNED UINT64 *)(process + offset);
        UINT32 i;

        candidate = prot_cr3_key(candidate);
        if (!candidate || candidate == kernel_cr3)
            continue;
        for (i = 0; i < count; i++)
        {
            UINT64 pa = prot_translate(candidate, pages[i].gva);
            if (!pa || (pa / PAGE_SIZE) != pages[i].real_pfn)
                break;
        }
        if (i == count)
            return candidate;
    }
    return kernel_cr3;
}


static BOOLEAN
prot_ensure_dummy(VOID)
{
    PHYSICAL_ADDRESS max_phys;

    if (g_prot_dummy_va)
        return TRUE;
    max_phys.QuadPart = MAXULONG64;
    g_prot_dummy_va = MmAllocateContiguousMemory(
        HV_PROTECT_MAX_PAGES * PAGE_SIZE,
        max_phys);
    if (!g_prot_dummy_va)
        return FALSE;
    RtlZeroMemory(
        g_prot_dummy_va,
        HV_PROTECT_MAX_PAGES * PAGE_SIZE);
    g_prot_dummy_pfn = va_to_pa(g_prot_dummy_va) / PAGE_SIZE;
    if (!g_prot_dummy_pfn)
    {
        MmFreeContiguousMemory(g_prot_dummy_va);
        g_prot_dummy_va = NULL;
        return FALSE;
    }
    ept_conceal_register_va(
        g_prot_dummy_va,
        HV_PROTECT_MAX_PAGES * PAGE_SIZE);
    return TRUE;
}

static BOOLEAN
prot_rip_allowed(UINT64 cr3_key, UINT64 rip)
{
    UINT32 i;
    UINT32 owner;
    UINT32 b;
    UINT32 e;

    if (!prot_owner_of(cr3_key, &owner))
        return FALSE;

    b = g_prot_owners[owner].page_begin;
    e = b + g_prot_owners[owner].page_count;
    for (i = b; i < e && i < g_prot_page_count; i++)
    {
        if ((rip & ~0xFFFULL) ==
            (g_prot_pages[i].gva & ~0xFFFULL))
            return TRUE;
    }
    for (i = 0; i < g_prot_wl_count; i++)
    {
        if (g_prot_wl[i].owner == owner &&
            rip >= g_prot_wl[i].gva &&
            rip < g_prot_wl[i].end)
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN
prot_find_page(UINT64 gpa, UINT32 * idx)
{
    UINT32 i;
    gpa &= ~0xFFFULL;
    for (i = 0; i < g_prot_page_count; i++)
    {
        if (g_prot_pages[i].gpa == gpa)
        {
            *idx = i;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
prot_arm_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 controls = 0;
    if (!vmx_vmread_checked(
            vcpu, VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &controls))
        return FALSE;
    return vmx_vmwrite_checked(
        vcpu, VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
        controls | CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG);
}

static BOOLEAN
prot_kva_shadow_enabled(VOID)
{
    ULONG flags = 0;
    ULONG returned = 0;
    NTSTATUS status = ZwQuerySystemInformation(
        196,
        &flags, sizeof(flags), &returned);
    return NT_SUCCESS(status) && (flags & 1U) != 0;
}

static BOOLEAN
prot_vcpus_ready(VOID)
{
    UINT32 cpu;

    if (!g_vcpu || !g_cpu_count)
        return FALSE;
    for (cpu = 0; cpu < g_cpu_count; cpu++)
    {
        if (!g_vcpu[cpu].launched ||
            g_vcpu[cpu].detached ||
            g_vcpu[cpu].failed ||
            g_vcpu[cpu].terminal)
            return FALSE;
    }
    return TRUE;
}


static VOID
prot_release_mdl(PMDL mdl)
{
    if (!mdl)
        return;
    if (mdl->MdlFlags & MDL_PAGES_LOCKED)
        MmUnlockPages(mdl);
    IoFreeMdl(mdl);
}


static VOID
prot_process_notify(
    PEPROCESS process,
    HANDLE process_id,
    PPS_CREATE_NOTIFY_INFO create_info)
{
    UINT32 owner;
    UINT32 cpu;
    PMDL mdl = NULL;
    PEPROCESS referenced = NULL;
    BOOLEAN invalidated = TRUE;
    KIRQL old;

    UNREFERENCED_PARAMETER(process_id);
    if (create_info || !g_prot_ready || !process)
        return;

    ExAcquireFastMutex(&g_prot_registration_mutex);
    for (owner = 0; owner < g_prot_owner_count; owner++)
    {
        if (!g_prot_owners[owner].active ||
            g_prot_owners[owner].process != process)
            continue;

        KeAcquireSpinLock(&g_prot_lock, &old);
        g_prot_owners[owner].active = FALSE;
        MemoryBarrier();
        KeReleaseSpinLock(&g_prot_lock, old);

        broadcast_protect_refresh();
        if (invalidated)
        {
            for (cpu = 0; cpu < g_cpu_count; cpu++)
            {
                if (g_vcpu[cpu].failed || g_vcpu[cpu].terminal)
                {
                    invalidated = FALSE;
                    break;
                }
            }
        }

        if (invalidated)
        {
            KeAcquireSpinLock(&g_prot_lock, &old);
            mdl = g_prot_owners[owner].mdl;
            referenced = g_prot_owners[owner].process;
            g_prot_owners[owner].mdl = NULL;
            g_prot_owners[owner].process = NULL;
            KeReleaseSpinLock(&g_prot_lock, old);
        }
        else
        {
            /* Keep pages pinned if any EPTP could still reference them. */
            KeAcquireSpinLock(&g_prot_lock, &old);
            g_prot_owners[owner].active = TRUE;
            MemoryBarrier();
            KeReleaseSpinLock(&g_prot_lock, old);
            broadcast_protect_refresh();
        }
        break;
    }
    ExReleaseFastMutex(&g_prot_registration_mutex);

    if (invalidated)
    {
        prot_release_mdl(mdl);
        if (referenced)
            ObDereferenceObject(referenced);
    }
}


NTSTATUS
protect_add_whitelist(UINT64 owner_cr3, UINT64 gva, UINT64 size)
{
    KIRQL   old;
    UINT64  current_cr3 = prot_cr3_key(__readcr3());
    UINT32  owner = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (!g_prot_notify_registered ||
        !prot_owner_of(current_cr3, &owner))
        return STATUS_NOT_FOUND;
    if (!gva || !size || gva + size < gva)
        return STATUS_INVALID_PARAMETER;
    if (owner_cr3 && !prot_owner_matches(
            owner, prot_cr3_key(owner_cr3)))
        return STATUS_NOT_SUPPORTED;
    owner_cr3 = current_cr3;

    ExAcquireFastMutex(&g_prot_registration_mutex);
    KeAcquireSpinLock(&g_prot_lock, &old);
    if (g_prot_wl_count >= HV_PROTECT_MAX_WHITELIST)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        g_prot_wl[g_prot_wl_count].owner = owner;
        g_prot_wl[g_prot_wl_count].gva = gva;
        g_prot_wl[g_prot_wl_count].end = gva + size;
        MemoryBarrier();
        g_prot_wl_count++;
    }
    KeReleaseSpinLock(&g_prot_lock, old);
    ExReleaseFastMutex(&g_prot_registration_mutex);
    return status;
}

NTSTATUS
protect_add_range(UINT64 owner_cr3, UINT64 gva, UINT64 size)
{
    KIRQL            old;
    UINT32           owner;
    UINT32           count;
    UINT32           i;
    UINT32           cpu;
    UINT64           page;
    UINT64           current_cr3;
    UINT64           user_cr3;
    PMDL             mdl = NULL;
    PPFN_NUMBER      mdl_pfns = NULL;
    HV_PROTECT_PAGE *pending = NULL;
    NTSTATUS         status = STATUS_UNSUCCESSFUL;

#if USE_PRIVATE_HOST_CR3
    return STATUS_NOT_SUPPORTED;
#endif

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (!g_prot_notify_registered)
        return STATUS_NOT_SUPPORTED;
    if (!prot_vcpus_ready())
        return STATUS_DEVICE_NOT_READY;
    if (!gva || !size || gva + size < gva ||
        size > HV_PROTECT_MAX_PAGES * PAGE_SIZE ||
        size > MAXULONG ||
        gva > (UINT64)MmHighestUserAddress ||
        gva + size - 1 > (UINT64)MmHighestUserAddress)
        return STATUS_INVALID_PARAMETER;
    if (!g_ept || !g_ept->mtf_supported ||
        !g_ept->execute_only_supported)
        return STATUS_NOT_SUPPORTED;

    current_cr3 = prot_cr3_key(__readcr3());
    if (owner_cr3 && prot_cr3_key(owner_cr3) != current_cr3)
        return STATUS_NOT_SUPPORTED;
    owner_cr3 = current_cr3;

    page = gva & ~0xFFFULL;
    count = (UINT32)((((gva & 0xFFFULL) + size) +
                      PAGE_SIZE - 1) >> PAGE_SHIFT);
    if (!count || count > HV_PROTECT_MAX_PAGES)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_prot_registration_mutex);

    if (!prot_ensure_dummy())
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    if (prot_owner_of(owner_cr3, &owner) ||
        g_prot_owner_count >= HV_PROTECT_MAX_OWNERS ||
        g_prot_page_count + count > HV_PROTECT_MAX_PAGES)
    {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto cleanup;
    }

    mdl = IoAllocateMdl(
        (PVOID)page, count * PAGE_SIZE,
        FALSE, FALSE, NULL);
    if (!mdl)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    __try
    {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        goto cleanup;
    }
    if (mdl->MdlFlags & MDL_IO_SPACE)
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }
    mdl_pfns = MmGetMdlPfnArray(mdl);
    if (!mdl_pfns)
    {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }

    pending = (HV_PROTECT_PAGE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*pending) * count,
        HV_POOL_TAG);
    if (!pending)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    RtlZeroMemory(pending, sizeof(*pending) * count);

    for (i = 0; i < count; i++, page += PAGE_SIZE)
    {
        PFN_NUMBER pfn = mdl_pfns[i];
        if (!pfn || pfn == (PFN_NUMBER)-1)
        {
            status = STATUS_NOT_FOUND;
            goto cleanup;
        }
        pending[i].gpa      = ((UINT64)pfn) << PAGE_SHIFT;
        pending[i].gva      = page;
        pending[i].real_pfn = (UINT64)pfn;
    }

    for (i = 0; i < count; i++)
    {
        UINT32 j;
        UINT32 existing;
        if (prot_find_page(pending[i].gpa, &existing))
        {
            status = STATUS_CONFLICTING_ADDRESSES;
            goto cleanup;
        }
        for (j = 0; j < i; j++)
        {
            if (pending[j].gpa == pending[i].gpa)
            {
                status = STATUS_CONFLICTING_ADDRESSES;
                goto cleanup;
            }
        }
    }

    user_cr3 = prot_find_user_cr3(owner_cr3, pending, count);
    if (user_cr3 == owner_cr3 && prot_kva_shadow_enabled())
    {
        status = STATUS_NOT_SUPPORTED;
        goto cleanup;
    }

    for (cpu = 0; cpu < g_cpu_count; cpu++)
    {
        for (i = 0; i < count; i++)
        {
            if (!ept_split_large_page(&g_vcpu[cpu], pending[i].gpa))
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto cleanup;
            }
        }
    }

    /*
    * Publish an immutable prefix before changing live leaves.  The EPT
    * rollout uses atomic 64-bit entries; a vCPU entering the policy during
    * rollout can already resolve the page and recover the correct view.
    */
    KeAcquireSpinLock(&g_prot_lock, &old);
    owner = g_prot_owner_count;
    g_prot_owners[owner].kernel_cr3 = owner_cr3;
    g_prot_owners[owner].user_cr3   = user_cr3;
    g_prot_owners[owner].process    = PsGetCurrentProcess();
    g_prot_owners[owner].mdl        = mdl;
    g_prot_owners[owner].page_begin = g_prot_page_count;
    g_prot_owners[owner].page_count = count;
    g_prot_owners[owner].active     = TRUE;
    ObReferenceObject(g_prot_owners[owner].process);
    for (i = 0; i < count; i++)
    {
        pending[i].owner = owner;
        g_prot_pages[g_prot_page_count + i] = pending[i];
    }
    mdl = NULL;
    MemoryBarrier();
    g_prot_page_count += count;
    g_prot_owner_count++;
    g_prot_ready = TRUE;
    KeReleaseSpinLock(&g_prot_lock, old);

    /*
    * Refresh each EPTP from the CR3 actually running on that processor.
    * The DPC enters VMX root locally, installs owner/dummy leaves, and does
    * a local INVEPT before acknowledging the rendezvous.
    */
    broadcast_protect_refresh();

    for (cpu = 0; cpu < g_cpu_count; cpu++)
    {
        if (g_vcpu[cpu].failed || g_vcpu[cpu].terminal)
        {
            status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }
    }

    HV_LOG(0, 0,
        "[hv] protect: cr3=0x%llx gva=0x%llx +%llu -> %u pages\n",
        owner_cr3, gva, size, count);
    status = STATUS_SUCCESS;

cleanup:
    if (pending)
        ExFreePoolWithTag(pending, HV_POOL_TAG);
    if (mdl)
        prot_release_mdl(mdl);
    ExReleaseFastMutex(&g_prot_registration_mutex);
    return status;
}


VOID
protect_on_cr3_load(VIRTUAL_MACHINE_STATE * vcpu, UINT64 new_cr3)
{
    UINT32  owner = 0;
    BOOLEAN is_owner;

    if (!g_prot_ready || !vcpu)
        return;

    is_owner = prot_owner_of(prot_cr3_key(new_cr3), &owner);
    if (!prot_apply_vcpu(vcpu, FALSE, 0, g_prot_page_count))
        goto failed;
    if (is_owner &&
        !prot_apply_vcpu(vcpu, TRUE,
                         g_prot_owners[owner].page_begin,
                         g_prot_owners[owner].page_count))
        goto failed;

    if (!ept_invept_single(vcpu))
        goto failed;
    return;

failed:
    vcpu->failed = TRUE;
    vcpu->terminal = TRUE;
    vcpu->last_failure = HV_FAILURE_EPT_MISCONFIGURATION;
}

/*
*   VMX-root.  Return TRUE if the violation was ours.
*/
BOOLEAN
protect_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 gpa)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
    UINT32 idx;
    UINT32 id;
    UINT64 rip = 0;
    UINT64 cr3 = 0;
    UINT64 gla = 0;
    BOOLEAN owner_view;
    BOOLEAN allow;

    if (!g_prot_ready || !vcpu)
        return FALSE;
    if (!prot_find_page(gpa, &idx))
        return FALSE;

    qual.AsUInt = vcpu->exit_qual;
    __vmx_vmread(VMCS_GUEST_RIP, &rip);
    __vmx_vmread(VMCS_GUEST_CR3, &cr3);
    owner_view = prot_owner_matches(
        g_prot_pages[idx].owner,
        prot_cr3_key(cr3));

    /*
    * A non-owner normally uses the RW dummy mapping.  A stale translation
    * can still exit after a CR3 switch; repair it and retry.  Execution from
    * the dummy view is never permitted.
    */
    if (!owner_view)
    {
        if (qual.ExecuteAccess)
        {
            UINT32 error_code = 0x10;
            if (!qual.ValidGuestLinearAddress)
                goto root_failed;
            __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &gla);
            if (qual.UserModeLinearAddress)
                error_code |= 0x4;
            vmexit_inject_pf(error_code, gla);
            vcpu->advance_rip = FALSE;
            return TRUE;
        }
        if (!prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                           g_prot_dummy_pfn + idx, TRUE, TRUE, FALSE) ||
            !ept_invept_single(vcpu))
            goto root_failed;
        vcpu->advance_rip = FALSE;
        return TRUE;
    }

    /* Owner baseline is the real PFN, execute-only. */
    if (qual.ExecuteAccess)
    {
        if (!prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                           g_prot_pages[idx].real_pfn,
                           FALSE, FALSE, TRUE) ||
            !ept_invept_single(vcpu))
            goto root_failed;
        vcpu->advance_rip = FALSE;
        return TRUE;
    }

    allow = prot_rip_allowed(prot_cr3_key(cr3), rip);
    id = vcpu->core_id < MAX_PROCESSORS ? vcpu->core_id : 0;

    if (allow)
    {
        if (!prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                           g_prot_pages[idx].real_pfn,
                           TRUE, (BOOLEAN)qual.WriteAccess, TRUE))
            goto root_failed;
    }
    else if (!prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                            g_prot_dummy_pfn + idx,
                            TRUE, (BOOLEAN)qual.WriteAccess, FALSE))
    {
        goto root_failed;
    }

    {
        UINT8 n;
        BOOLEAN found = FALSE;
        for (n = 0; n < g_prot_mtf_count[id]; n++)
        {
            if (g_prot_mtf_gpa[id][n] == g_prot_pages[idx].gpa)
            {
                found = TRUE;
                break;
            }
        }
        if (!found)
        {
            if (g_prot_mtf_count[id] >= HV_PROTECT_MAX_MTF_PAGES)
                goto root_failed;
            n = g_prot_mtf_count[id]++;
            g_prot_mtf_gpa[id][n] = g_prot_pages[idx].gpa;
        }
        if (!allow && qual.WriteAccess)
            g_prot_mtf_zero[id][n] = 1;
    }
    if (!prot_arm_mtf(vcpu) || !ept_invept_single(vcpu))
        goto root_failed;
    vcpu->advance_rip = FALSE;
    return TRUE;

root_failed:
    vcpu->failed = TRUE;
    vcpu->terminal = TRUE;
    vcpu->last_failure = HV_FAILURE_EPT_MISCONFIGURATION;
    vcpu->advance_rip = FALSE;
    return TRUE;
}

BOOLEAN
protect_mtf_pending(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT32 id;
    if (!vcpu)
        return FALSE;
    id = vcpu->core_id < MAX_PROCESSORS ? vcpu->core_id : 0;
    return g_prot_mtf_count[id] != 0;
}

VOID
protect_on_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT32 id;
    UINT8 n;
    UINT64 cr3 = 0;

    if (!vcpu)
        return;
    id = vcpu->core_id < MAX_PROCESSORS ? vcpu->core_id : 0;
    if (!g_prot_mtf_count[id])
        return;

    __vmx_vmread(VMCS_GUEST_CR3, &cr3);
    for (n = 0; n < g_prot_mtf_count[id]; n++)
    {
        UINT32 idx;
        if (prot_find_page(g_prot_mtf_gpa[id][n], &idx))
        {
            BOOLEAN owner_view = prot_owner_matches(
                g_prot_pages[idx].owner,
                prot_cr3_key(cr3));
            BOOLEAN ok;

            if (owner_view)
                ok = prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                                   g_prot_pages[idx].real_pfn,
                                   FALSE, FALSE, TRUE);
            else
                ok = prot_set_leaf(vcpu, g_prot_pages[idx].gpa,
                                   g_prot_dummy_pfn + idx,
                                   TRUE, TRUE, FALSE);
            if (!ok)
                goto failed;
            if (g_prot_mtf_zero[id][n])
                RtlZeroMemory(
                    (PUCHAR)g_prot_dummy_va + idx * PAGE_SIZE,
                    PAGE_SIZE);
        }
    }

    g_prot_mtf_count[id] = 0;
    RtlZeroMemory(
        g_prot_mtf_gpa[id],
        sizeof(g_prot_mtf_gpa[id]));
    RtlZeroMemory(
        g_prot_mtf_zero[id],
        sizeof(g_prot_mtf_zero[id]));
    if (!ept_invept_single(vcpu))
        goto failed;
    return;

failed:
    g_prot_mtf_count[id] = 0;
    RtlZeroMemory(
        g_prot_mtf_gpa[id],
        sizeof(g_prot_mtf_gpa[id]));
    RtlZeroMemory(
        g_prot_mtf_zero[id],
        sizeof(g_prot_mtf_zero[id]));
    vcpu->failed = TRUE;
    vcpu->terminal = TRUE;
    vcpu->last_failure = HV_FAILURE_EPT_MISCONFIGURATION;
}

VOID
protect_query_status(HV_PROTECT_STATUS_V1 * status)
{
    KIRQL old;
    UINT32 i;

    if (!status)
        return;
    RtlZeroMemory(status, sizeof(*status));
    status->Size = sizeof(*status);
    status->Version = HV_PROTECT_STATUS_VERSION_1;
    status->MaximumPages = HV_PROTECT_MAX_PAGES;

    if (g_ept && g_ept->mtf_supported)
        status->Flags |= HV_PROTECT_STATUS_MTF;
    if (g_ept && g_ept->execute_only_supported)
        status->Flags |= HV_PROTECT_STATUS_EXECUTE_ONLY;
    if (g_prot_notify_registered)
        status->Flags |= HV_PROTECT_STATUS_PROCESS_NOTIFY;
#if !OPHION_PRODUCTION && !USE_PRIVATE_HOST_CR3
    if (g_prot_dummy_va &&
        (status->Flags & HV_PROTECT_STATUS_MTF) &&
        (status->Flags & HV_PROTECT_STATUS_EXECUTE_ONLY) &&
        (status->Flags & HV_PROTECT_STATUS_PROCESS_NOTIFY))
        status->Flags |= HV_PROTECT_STATUS_AVAILABLE;
#endif

    KeAcquireSpinLock(&g_prot_lock, &old);
    status->ProtectedPages = g_prot_page_count;
    status->WhitelistRanges = g_prot_wl_count;
    for (i = 0; i < g_prot_owner_count; i++)
    {
        if (!g_prot_owners[i].active)
            continue;
        status->ActiveOwners++;
        if (g_prot_owners[i].user_cr3 !=
            g_prot_owners[i].kernel_cr3)
            status->Flags |= HV_PROTECT_STATUS_KPTI_DUAL_ROOT;
    }
    if (status->ActiveOwners)
        status->Flags |= HV_PROTECT_STATUS_ACTIVE;
    KeReleaseSpinLock(&g_prot_lock, old);
}

NTSTATUS
protect_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io)
{
    HV_PROTECT_RANGE_REQUEST * req;
    ULONG in_len = io->Parameters.DeviceIoControl.InputBufferLength;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    if (irp->RequestorMode != UserMode)
        return STATUS_ACCESS_DENIED;
    if (in_len < sizeof(*req))
        return STATUS_BUFFER_TOO_SMALL;
    req = (HV_PROTECT_RANGE_REQUEST *)irp->AssociatedIrp.SystemBuffer;
    if (!req || req->Reserved != 0 ||
        (req->Flags != 0 &&
         req->Flags != HV_PROTECT_FLAG_WHITELIST))
        return STATUS_INVALID_PARAMETER;

    irp->IoStatus.Information = 0;
    if (req->Flags == HV_PROTECT_FLAG_WHITELIST)
        return protect_add_whitelist(
            req->OwnerCr3, req->GuestVa, req->Size);
    return protect_add_range(
        req->OwnerCr3, req->GuestVa, req->Size);
}

VOID
protect_init(VOID)
{
    KeInitializeSpinLock(&g_prot_lock);
    ExInitializeFastMutex(&g_prot_registration_mutex);

#if !OPHION_PRODUCTION
    {
        NTSTATUS status;
        if (!prot_ensure_dummy())
            HV_LOG(0, 0, "[hv] protect: decoy allocation unavailable\n");

        status = PsSetCreateProcessNotifyRoutineEx(
            prot_process_notify, FALSE);
        g_prot_notify_registered = NT_SUCCESS(status);
        if (!g_prot_notify_registered)
            HV_LOG(0, 0,
                "[hv] protect: process lifetime callback unavailable: 0x%08X\n",
                status);
    }
#endif
}

VOID
protect_destroy(VOID)
{
    UINT32 i;

    if (g_prot_notify_registered)
    {
        (VOID)PsSetCreateProcessNotifyRoutineEx(
            prot_process_notify, TRUE);
        g_prot_notify_registered = FALSE;
    }

    for (i = 0; i < g_prot_owner_count; i++)
    {
        prot_release_mdl(g_prot_owners[i].mdl);
        g_prot_owners[i].mdl = NULL;
        if (g_prot_owners[i].process)
        {
            ObDereferenceObject(g_prot_owners[i].process);
            g_prot_owners[i].process = NULL;
        }
    }

    if (g_prot_dummy_va)
    {
        MmFreeContiguousMemory(g_prot_dummy_va);
        g_prot_dummy_va = NULL;
        g_prot_dummy_pfn = 0;
    }
    RtlZeroMemory(g_prot_mtf_gpa, sizeof(g_prot_mtf_gpa));
    RtlZeroMemory(g_prot_mtf_zero, sizeof(g_prot_mtf_zero));
    RtlZeroMemory(g_prot_mtf_count, sizeof(g_prot_mtf_count));
    RtlZeroMemory(g_prot_pages, sizeof(g_prot_pages));
    RtlZeroMemory(g_prot_owners, sizeof(g_prot_owners));
    RtlZeroMemory(g_prot_wl, sizeof(g_prot_wl));
    g_prot_page_count  = 0;
    g_prot_owner_count = 0;
    g_prot_wl_count    = 0;
    g_prot_ready       = FALSE;
}

#else

VOID     protect_init(VOID) {}
VOID     protect_destroy(VOID) {}
BOOLEAN  protect_requires_cr3_exiting(VOID) { return FALSE; }
VOID     protect_on_cr3_load(VIRTUAL_MACHINE_STATE * v, UINT64 c)
{
    UNREFERENCED_PARAMETER(v);
    UNREFERENCED_PARAMETER(c);
}
BOOLEAN  protect_handle_violation(VIRTUAL_MACHINE_STATE * v, UINT64 g)
{
    UNREFERENCED_PARAMETER(v);
    UNREFERENCED_PARAMETER(g);
    return FALSE;
}
VOID     protect_on_mtf(VIRTUAL_MACHINE_STATE * v)
{
    UNREFERENCED_PARAMETER(v);
}
BOOLEAN  protect_mtf_pending(VIRTUAL_MACHINE_STATE * v)
{
    UNREFERENCED_PARAMETER(v);
    return FALSE;
}
NTSTATUS protect_handle_ioctl(PIRP i, PIO_STACK_LOCATION s)
{
    UNREFERENCED_PARAMETER(i);
    UNREFERENCED_PARAMETER(s);
    return STATUS_NOT_SUPPORTED;
}
VOID protect_query_status(HV_PROTECT_STATUS_V1 * status)
{
    if (!status)
        return;
    RtlZeroMemory(status, sizeof(*status));
    status->Size = sizeof(*status);
    status->Version = HV_PROTECT_STATUS_VERSION_1;
}
NTSTATUS protect_add_range(UINT64 a, UINT64 b, UINT64 c)
{
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    return STATUS_NOT_SUPPORTED;
}
NTSTATUS protect_add_whitelist(UINT64 a, UINT64 b, UINT64 c)
{
    UNREFERENCED_PARAMETER(a);
    UNREFERENCED_PARAMETER(b);
    UNREFERENCED_PARAMETER(c);
    return STATUS_NOT_SUPPORTED;
}

#endif
