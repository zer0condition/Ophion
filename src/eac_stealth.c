/*
*   eac_stealth.c - EAC-specific kernel counter-measures
*
*   Targets verified from the EasyAntiCheat.sys / EasyAntiCheat_EOS.sys RE
*   (falz331 UC 748063, lolz5465az UC 749306):
*
*     1. KdEnteredDebugger / KdDebuggerEnabled direct checks
*        -> patch the exported Kd data globals (data, not PatchGuard text).
*
*     2. NtQuerySystemInformation class 0xC5 hypervisor presence probing.
*        -> the kernel answer derives from CPUID 0x40000000+ leaves which
*           stealth.c already fakes as bare metal; the residual leak is the
*           boot-time cached state in KUSER_SHARED_DATA ProcessorFeatures.
*           scrub the virtualization-present feature bits.
*
*     3. HalAcpiGetTableEx(DMAR) + raw physical scan of the DMAR tables
*        used to enumerate IOMMU/DMA configuration.
*        -> pull the DMAR table via AuxKlib and register its physical pages
*           into the EPT conceal ranges, so post-launch physical scanners
*           (MmMapIoSpace/MmCopyMemory walkers) read the zero dummy page.
*
*     4. RtlWalkFrameChain 1%-sampled stack capture + return-address range
*        validation against known module ranges.
*        -> Ophion registers no kernel callbacks and runs no guest code, so
*           its own frames never appear in a captured chain.  the exposed
*           surface is the BYOVD loader dispatch path.  eac_stack_scrub()
*           rewrites kernel stack slots pointing into concealed (hidden)
*           ranges to a benign ntoskrnl address before the caller returns.
*
*     5. VslGetSecurePciEnabled VBS probe.
*        -> optional VMX-root text neuter (xor eax,eax; ret).  default off:
*           PatchGuard verifies ntoskrnl .text; enable for testing only.
*
*     6. SeRegisterImageVerificationCallback.
*        -> ordering defense: Ophion + BYOVD load before EAC registers its
*           callback, so the callback never observes us.  no patch needed.
*/

#include "hv.h"
#include <ntimage.h>
#include <aux_klib.h>

#ifndef STEALTH_EAC
#define STEALTH_EAC 1
#endif

#ifndef STEALTH_EAC_PATCH_VSL
#define STEALTH_EAC_PATCH_VSL 0
#endif

/*
* Kernel-global and firmware mutations are experimental.  Keep the default
* profile observation-only: direct Kd/KUSER/HVL/SMBIOS/DMAR changes can
* violate PatchGuard or make Windows observe contradictory platform state.
*/
#ifndef STEALTH_EAC_PATCH_KD
#define STEALTH_EAC_PATCH_KD 0
#endif
#ifndef STEALTH_EAC_PATCH_KSD
#define STEALTH_EAC_PATCH_KSD 0
#endif
#ifndef STEALTH_EAC_CONCEAL_DMAR
#define STEALTH_EAC_CONCEAL_DMAR 0
#endif
#ifndef STEALTH_EAC_ZERO_HVL
#define STEALTH_EAC_ZERO_HVL 0
#endif
#ifndef STEALTH_EAC_SPOOF_SMBIOS
#define STEALTH_EAC_SPOOF_SMBIOS 0
#endif


#if STEALTH_EAC

#pragma comment(lib, "Aux_Klib.lib")

#define ACPI_PROVIDER_SIG 'IPCA'
#define ACPI_DMAR_SIG     'RMAD'

//
// local constants not in the shared headers
#define KSD_PROCESSOR_FEATURES_OFF  0x274   /* verified on 26200 via ntdll!RtlIsProcessorFeaturePresent byte-load path */
#define EAC_KERNEL_VA_BASE      0xFFFF800000000000ULL
#define EAC_KERNEL_STACK_SIZE   0x10000
#define EAC_CR0_WRITE_PROTECT   0x00010000ULL

//
// KUSER_SHARED_DATA (x64) layout constants
//
#define KSD_BASE_VA                 0x7FFE0000ULL
#define PF_VIRT_FIRMWARE_ENABLED    21

typedef struct _EAC_STEALTH_STATE {
    BOOLEAN kd_patched;
    BOOLEAN ksd_scrubbed;
    BOOLEAN dmar_concealed;
    ULONG   dmar_pages;
    ULONG   scrub_passes;
    ULONG   scrub_rewrites;
} EAC_STEALTH_STATE;

static EAC_STEALTH_STATE g_eac;

/* ----------------------------------------------------------------
 * helpers
 * ---------------------------------------------------------------- */

static PVOID
eac_routine(PCWSTR name)
{
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    return MmGetSystemRoutineAddress(&us);
}

static PUCHAR
eac_nt_base(VOID)
{
    static PUCHAR cached;
    PUCHAR page;
    ULONG  i;

    if (cached)
        return cached;

    page = (PUCHAR)eac_routine(L"KeGetCurrentIrql");
    if (!page)
        return NULL;

    page = (PUCHAR)((UINT64)page & ~(UINT64)(PAGE_SIZE - 1));
    for (i = 0; i < 0x800; i++)
    {
        if (((PIMAGE_DOS_HEADER)page)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            PIMAGE_NT_HEADERS64 nt =
                (PIMAGE_NT_HEADERS64)(page +
                    ((PIMAGE_DOS_HEADER)page)->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
            {
                cached = page;
                return page;
            }
        }
        page -= PAGE_SIZE;
    }
    return NULL;
}

/* ----------------------------------------------------------------
 * 1. Kd debugger globals
 * ---------------------------------------------------------------- */

static VOID
eac_patch_kd_globals(VOID)
{
    PUCHAR enabled    = (PUCHAR)eac_routine(L"KdDebuggerEnabled");
    PUCHAR entered    = (PUCHAR)eac_routine(L"KdEnteredDebugger");
    PUCHAR notpresent = (PUCHAR)eac_routine(L"KdDebuggerNotPresent");

    if (enabled)
    {
        *enabled = 0;
        g_eac.kd_patched = TRUE;
    }
    if (entered)
        *entered = 0;
    if (notpresent)
        *notpresent = 1;
}

/* ----------------------------------------------------------------
 * 2. KUSER_SHARED_DATA virtualization feature scrub
* ---------------------------------------------------------------- */

static VOID
eac_scrub_ksd(VOID)
{
    PUCHAR features = (PUCHAR)(KSD_BASE_VA + KSD_PROCESSOR_FEATURES_OFF);

    if (features[PF_VIRT_FIRMWARE_ENABLED])
    {
        features[PF_VIRT_FIRMWARE_ENABLED] = 0;
        g_eac.ksd_scrubbed = TRUE;
    }
}

/* ----------------------------------------------------------------
 * 3. DMAR table physical conceal
 * ---------------------------------------------------------------- */

static VOID
eac_conceal_dmar(VOID)
{
    NTSTATUS status;
    ULONG    size = 0;
    PVOID    table;
    UINT64   table_pa;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
        return;

    status = AuxKlibGetSystemFirmwareTable(
        ACPI_PROVIDER_SIG, ACPI_DMAR_SIG, NULL, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL || !size)
        return;

    table = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, HV_POOL_TAG);
    if (!table)
        return;

    status = AuxKlibGetSystemFirmwareTable(
        ACPI_PROVIDER_SIG, ACPI_DMAR_SIG, table, size, &size);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(table, HV_POOL_TAG);
        return;
    }

    table_pa = va_to_pa(table);
    if (table_pa)
    {
        ept_conceal_register_pa(table_pa, size);
        g_eac.dmar_pages = (ULONG)((size + PAGE_SIZE - 1) >> PAGE_SHIFT);

        /*
        * keep the allocation alive for the lifetime of the HV: the
        * physical pages are now permanently concealed, so freeing them
        * would send live PFNs back to the pool and make unrelated
        * future allocations read as the zero dummy page in the guest.
        * intentional one-time leak of a few pages.
        */
        g_eac.dmar_concealed = TRUE;
        return;
    }

    g_eac.dmar_concealed = FALSE;
    ExFreePoolWithTag(table, HV_POOL_TAG);
}

static VOID
eac_conceal_dmar_firmware(VOID)
{
    PHYSICAL_ADDRESS phys;
    PUCHAR           rom;
    ULONG            off;

    phys.QuadPart = 0xE0000;
    rom = (PUCHAR)MmMapIoSpace(phys, 0x20000, MmNonCached);
    if (!rom)
        return;

    for (off = 0; off + 8 < 0x20000; off += 16)
    {
        if (rom[off] == 'R' && rom[off+1] == 'S' &&
            rom[off+2] == 'D' && rom[off+3] == ' ' &&
            rom[off+4] == 'P' && rom[off+5] == 'T' &&
            rom[off+6] == 'R' && rom[off+7] == ' ')
        {
            UINT64 xsdt = 0;
            if (off + 36 <= 0x20000 && rom[off + 15] >= 2)
                xsdt = *(UINT64 *)(rom + off + 24);
            if (xsdt)
            {
                PHYSICAL_ADDRESS xp;
                PUCHAR           xv;
                UINT32           len;
                UINT32           i;

                xp.QuadPart = xsdt & ~0xFFFULL;
                xv = (PUCHAR)MmMapIoSpace(xp, PAGE_SIZE * 2, MmNonCached);
                if (xv)
                {
                    PUCHAR hdr = xv + (xsdt & 0xFFF);
                    if (hdr[0]=='X' && hdr[1]=='S' &&
                        hdr[2]=='D' && hdr[3]=='T')
                    {
                        len = *(UINT32 *)(hdr + 4);
                        for (i = 36; i + 8 <= len && i < PAGE_SIZE * 2; i += 8)
                        {
                            UINT64 tpa = *(UINT64 *)(hdr + i);
                            PHYSICAL_ADDRESS tp;
                            PUCHAR tv;
                            tp.QuadPart = tpa & ~0xFFFULL;
                            tv = (PUCHAR)MmMapIoSpace(tp, PAGE_SIZE, MmNonCached);
                            if (!tv)
                                continue;
                            if (tv[tpa & 0xFFF]=='R' &&
                                tv[(tpa & 0xFFF)+1]=='M' &&
                                tv[(tpa & 0xFFF)+2]=='A' &&
                                tv[(tpa & 0xFFF)+3]=='D')
                            {
                                UINT32 tlen = *(UINT32 *)(tv + (tpa & 0xFFF) + 4);
                                ept_conceal_register_pa(tpa, tlen ? tlen : PAGE_SIZE);
                                g_eac.dmar_pages +=
                                    (tlen + PAGE_SIZE - 1) >> PAGE_SHIFT;
                                g_eac.dmar_concealed = TRUE;
                            }
                            MmUnmapIoSpace(tv, PAGE_SIZE);
                        }
                    }
                    MmUnmapIoSpace(xv, PAGE_SIZE * 2);
                }
            }
            break;
        }
    }

    /* also hide any raw RMAD signature in the BIOS ROM window */
    for (off = 0; off + 4 < 0x20000; off += 4)
    {
        if (rom[off]=='R' && rom[off+1]=='M' &&
            rom[off+2]=='A' && rom[off+3]=='D')
        {
            ept_conceal_register_pa(0xE0000ULL + off, PAGE_SIZE);
            g_eac.dmar_concealed = TRUE;
        }
    }
    MmUnmapIoSpace(rom, 0x20000);
}

static VOID
eac_zero_hvl_connection(VOID)
{
    /*
    * HvlQueryConnection: mov rax,[rip+disp32]; test rax,rax; jz fail
    * Zeroing that data pointer makes the kernel report no HV connection.
    * Skip when a parent hypervisor is already present (VBS/Hyper-V root)
    * — tearing down their connection bugchecks the host.
    */
    PUCHAR fn;
    INT32  disp;
    UINT64 *slot;

    if (g_hv_capabilities.ParentFlags & HV_PARENT_PRESENT)
        return;

    fn = (PUCHAR)eac_routine(L"HvlQueryConnection");
    if (!fn || fn[0] != 0x48 || fn[1] != 0x8B || fn[2] != 0x05)
        return;
    disp = *(INT32 *)(fn + 3);
    slot = (UINT64 *)(fn + 7 + disp);
    if (MmIsAddressValid(slot))
        *slot = 0;
}



/* ----------------------------------------------------------------
 * 4. kernel stack scrub for concealed-range return addresses
 * ---------------------------------------------------------------- */

VOID
eac_stack_scrub(VOID)
{
    UINT64 rsp;
    UINT64 stack_base;
    UINT64 stack_limit;
    UINT64 benign;
    UINT64 slot;

    /*
    * benign target: an address inside ntoskrnl .text.  EAC's validation
    * checks module-range membership only, so any nt text address with a
    * valid unwind entry passes.  KeGetCurrentIrql is a leaf that unwinds
    * cleanly.
    */
    if (!eac_nt_base())
        return;
    benign = (UINT64)eac_routine(L"KeGetCurrentIrql");
    if (!benign)
        return;

    rsp         = (UINT64)_AddressOfReturnAddress();
    stack_base  = rsp & ~(UINT64)(EAC_KERNEL_STACK_SIZE - 1);
    stack_limit = stack_base + EAC_KERNEL_STACK_SIZE;

    g_eac.scrub_passes++;

    for (slot = (rsp + 8) & ~7ULL; slot + 8 <= stack_limit; slot += 8)
    {
        UINT64 value = *(UINT64 *)slot;
        UINT64 pa;

        if (value < EAC_KERNEL_VA_BASE)
            continue;

        pa = va_to_pa((PVOID)value);
        if (!pa)
            continue;

        if (ept_conceal_is_hidden(pa))
        {
            *(UINT64 *)slot = benign;
            g_eac.scrub_rewrites++;
        }
    }
}

/* ----------------------------------------------------------------
 * 5. optional VslGetSecurePciEnabled neuter (PG-risky, default off)
 * ---------------------------------------------------------------- */

#if STEALTH_EAC_PATCH_VSL
static VOID
eac_patch_vsl(VOID)
{
    PUCHAR fn = (PUCHAR)eac_routine(L"VslGetSecurePciEnabled");
    UINT64 cr0;

    if (!fn)
        return;

    cr0 = __readcr0();
    __writecr0(cr0 & ~EAC_CR0_WRITE_PROTECT);
    _Disable();
    fn[0] = 0x31; fn[1] = 0xC0;   // xor eax, eax
    fn[2] = 0xC3;                 // ret
    _Enable();
    __writecr0(cr0);
}
#endif

/* ----------------------------------------------------------------
 * master entry + diagnostics
 * ---------------------------------------------------------------- */

static VOID
eac_spoof_smbios(VOID)
{
    PHYSICAL_ADDRESS phys;
    PUCHAR           rom;
    ULONG            off;
    UINT32           cpu;

    phys.QuadPart = 0xF0000;
    rom = (PUCHAR)MmMapIoSpace(phys, 0x10000, MmNonCached);
    if (!rom)
        return;

    for (off = 0; off + 32 < 0x10000; off += 16)
    {
        BOOLEAN sm3 = rom[off]=='_' && rom[off+1]=='S' &&
                      rom[off+2]=='M' && rom[off+3]=='3' && rom[off+4]=='_';
        BOOLEAN sm  = rom[off]=='_' && rom[off+1]=='S' &&
                      rom[off+2]=='M' && rom[off+3]=='_';
        UINT64  table_pa = 0;
        UINT32  table_len = 0;
        PVOID   shadow;
        UINT64  shadow_pfn;

        if (!sm && !sm3)
            continue;
        if (sm3)
        {
            table_len = *(UINT32 *)(rom + off + 12);
            table_pa  = *(UINT64 *)(rom + off + 16);
        }
        else
        {
            table_len = *(UINT16 *)(rom + off + 0x16);
            table_pa  = *(UINT32 *)(rom + off + 0x18);
        }
        if (!table_pa || !table_len || table_len > 0x10000)
            continue;

        shadow = ExAllocatePool2(POOL_FLAG_NON_PAGED, table_len, HV_POOL_TAG);
        if (!shadow)
            break;
        {
            PHYSICAL_ADDRESS tp;
            PUCHAR tv;
            tp.QuadPart = table_pa & ~0xFFFULL;
            tv = (PUCHAR)MmMapIoSpace(tp,
                ((table_pa & 0xFFF) + table_len + PAGE_SIZE - 1) & ~0xFFFULL,
                MmNonCached);
            if (!tv)
            {
                ExFreePoolWithTag(shadow, HV_POOL_TAG);
                break;
            }
            RtlCopyMemory(shadow, tv + (table_pa & 0xFFF), table_len);
            MmUnmapIoSpace(tv,
                ((table_pa & 0xFFF) + table_len + PAGE_SIZE - 1) & ~0xFFFULL);
        }

        /* scramble type 1/2/3 string payloads (serial/uuid) */
        {
            PUCHAR p = (PUCHAR)shadow;
            PUCHAR e = p + table_len;
            while (p + 4 < e && p[1] >= 4)
            {
                if (p[0] == 1 || p[0] == 2 || p[0] == 3)
                    RtlFillMemory(p + 4, (SIZE_T)p[1] - 4, '0');
                p += p[1];
                while (p + 1 < e && !(p[0] == 0 && p[1] == 0))
                    p++;
                p += 2;
            }
        }

        shadow_pfn = va_to_pa(shadow) / PAGE_SIZE;
        if (shadow_pfn)
        {
            UINT64 pa = table_pa & ~0xFFFULL;
            for (cpu = 0; cpu < g_cpu_count; cpu++)
            {
                PEPT_PML1_ENTRY leaf;
                if (!ept_split_large_page(&g_vcpu[cpu], pa))
                    continue;
                leaf = ept_get_pml1(g_vcpu[cpu].ept_page_table, pa);
                if (!leaf)
                    continue;
                leaf->PageFrameNumber = shadow_pfn;
                leaf->ReadAccess = 1;
                leaf->WriteAccess = 0;
                leaf->ExecuteAccess = 0;
            }
        }
        break;
    }
    MmUnmapIoSpace(rom, 0x10000);
}

VOID
eac_stealth_apply(VOID)
{
    if (!g_stealth_enabled)
        return;

#if STEALTH_EAC_PATCH_KD
    eac_patch_kd_globals();
#endif
#if STEALTH_EAC_PATCH_KSD
    eac_scrub_ksd();
#endif
#if STEALTH_EAC_CONCEAL_DMAR
    eac_conceal_dmar();
    eac_conceal_dmar_firmware();
#endif
#if STEALTH_EAC_ZERO_HVL
    eac_zero_hvl_connection();
#endif
#if STEALTH_EAC_SPOOF_SMBIOS
    eac_spoof_smbios();
#endif
#if STEALTH_EAC_PATCH_VSL
    eac_patch_vsl();
#endif

    HV_LOG(0, 0,
        "[hv] AC profile: safe defaults; kd=%d ksd=%d dmar=%d (%u pages)\n",
        g_eac.kd_patched, g_eac.ksd_scrubbed,
        g_eac.dmar_concealed, g_eac.dmar_pages);
}

VOID
eac_stealth_query(PULONG flags, PULONG counters)
{
    if (flags)
    {
        *flags = 0;
        if (g_eac.kd_patched)     *flags |= 0x01;
        if (g_eac.ksd_scrubbed)   *flags |= 0x02;
        if (g_eac.dmar_concealed) *flags |= 0x04;
    }
    if (counters)
    {
        counters[0] = g_eac.dmar_pages;
        counters[1] = g_eac.scrub_passes;
        counters[2] = g_eac.scrub_rewrites;
    }
}

#else // !STEALTH_EAC

VOID eac_stealth_apply(VOID) {}
VOID eac_stack_scrub(VOID) {}
VOID eac_stealth_query(PULONG flags, PULONG counters)
{
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(counters);
}

#endif
