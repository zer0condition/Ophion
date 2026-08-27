/*
*   stealth.c - anti-detection stealth implementation
*   implements cpuid bare-metal caching and xcr0 validation
*/
#include "hv.h"

/*
*   initialize the bare-metal cpuid cache
*   must be called at passive_level before any vmxon
*   samples the cpu's native response for invalid leaves and
*/
VOID
stealth_init_cpuid_cache(VOID)
{
    INT32 cpu_info[4] = {0};
    __cpuidex(cpu_info, CPUID_PROCESSOR_FEATURES, 0);
    g_stealth_cpuid_cache.parent_hypervisor_present =
        ((UINT32)cpu_info[2] & HYPERV_HYPERVISOR_PRESENT_BIT) != 0;

    if (g_stealth_cpuid_cache.parent_hypervisor_present)
    {
        __cpuidex(cpu_info, 0x40000000, 0);
        if ((UINT32)cpu_info[1] == 0x7263694D &&
            (UINT32)cpu_info[2] == 0x666F736F &&
            (UINT32)cpu_info[3] == 0x76482074)
        {
            g_stealth_cpuid_cache.parent_is_hyperv = TRUE;
            if ((UINT32)cpu_info[0] >= 0x40000003)
            {
                __cpuidex(cpu_info, 0x40000003, 0);
                g_stealth_cpuid_cache.parent_hyperv_features =
                    (UINT32)cpu_info[0];
            }
        }
    }

    //
    // cache the response for an obviously invalid leaf.
    // on intel, CPUID returns the highest standard leaf's response
    // for any leaf between max_standard+1 and 0x7FFFFFFF.
    // for the hypervisor range (0x40000000-0x4FFFFFFF), on bare metal
    // without a hypervisor, the CPU also returns this same response.
    // anti-cheats compare responses across invalid leaves to detect inconsistency.
    //
    __cpuidex(cpu_info, 0x13371337, 0);
    g_stealth_cpuid_cache.invalid_leaf[0] = cpu_info[0];
    g_stealth_cpuid_cache.invalid_leaf[1] = cpu_info[1];
    g_stealth_cpuid_cache.invalid_leaf[2] = cpu_info[2];
    g_stealth_cpuid_cache.invalid_leaf[3] = cpu_info[3];

    __cpuidex(cpu_info, 0, 0);
    g_stealth_cpuid_cache.max_std_leaf = (UINT32)cpu_info[0];

    __cpuidex(cpu_info, (int)0x80000000, 0);
    g_stealth_cpuid_cache.max_ext_leaf = (UINT32)cpu_info[0];

    //
    // get hardware-supported XCR0 bitmask (CPUID.0Dh.0: EAX=low32, EDX=high32)
    // this tells us which XCR0 bits the CPU actually supports (PKRU, AMX, etc.)
    // used to validate XSETBV values instead of a hardcoded mask
    //
    __cpuidex(cpu_info, 0x0D, 0);
    g_stealth_cpuid_cache.valid_xcr0_mask =
        ((UINT64)(UINT32)cpu_info[3] << 32) | (UINT64)(UINT32)cpu_info[0];

    g_stealth_cpuid_cache.initialized = TRUE;

#if STEALTH_COMPENSATE_TIMING
    //
    // calibrate bare-metal CPUID execution cost.
    // take the minimum of many samples to filter out interrupt/scheduling noise.
    // must run before VMXON so we measure true hardware cost.
    //
    {
        UINT64 best = MAXULONG64;
        INT32  dummy[4];

        for (int i = 0; i < 200; i++)
        {
            _mm_lfence();
            UINT64 a = __rdtsc();
            _mm_lfence();
            __cpuidex(dummy, 0, 0);
            _mm_lfence();
            UINT64 b = __rdtsc();
            _mm_lfence();

            UINT64 delta = b - a;
            if (delta < best)
                best = delta;
        }

        g_stealth_cpuid_cache.bare_metal_cpuid_cost = best;
        g_stealth_cpuid_cache.bare_metal_fyl2xp1_cost = 0;

    }

    //
    // check if the CPU forces RDTSC exiting as a must-be-1 bit.
    // if so, we can't toggle it off dynamically — performance hit is
    // unavoidable but compensation still works via the armed flag.
    //
    {
        IA32_VMX_BASIC_REGISTER vmx_basic;
        vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);

        UINT32 msr_id = vmx_basic.VmxControls
            ? IA32_VMX_TRUE_PROCBASED_CTLS
            : IA32_VMX_PROCBASED_CTLS;

        MSR msr;
        msr.Flags = __readmsr(msr_id);

        g_stealth_cpuid_cache.rdtsc_exiting_forced =
            !!(msr.Fields.Low & CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING);
    }
#endif

    HV_LOG(0, 0, "[hv] Stealth CPUID cache: ParentHV=%d, MaxStd=0x%X, MaxExt=0x%X, XCR0=0x%llX, "
             "InvalidLeaf={0x%X, 0x%X, 0x%X, 0x%X}\n",
             g_stealth_cpuid_cache.parent_hypervisor_present,
             g_stealth_cpuid_cache.max_std_leaf,
             g_stealth_cpuid_cache.max_ext_leaf,
             g_stealth_cpuid_cache.valid_xcr0_mask,
             (UINT32)g_stealth_cpuid_cache.invalid_leaf[0],
             (UINT32)g_stealth_cpuid_cache.invalid_leaf[1],
             (UINT32)g_stealth_cpuid_cache.invalid_leaf[2],
             (UINT32)g_stealth_cpuid_cache.invalid_leaf[3]);

#if STEALTH_COMPENSATE_TIMING
    HV_LOG(0, 0, "[hv] TSC compensation: bare_metal_cpuid=%llu cycles, rdtsc_exiting_forced=%d\n",
             g_stealth_cpuid_cache.bare_metal_cpuid_cost,
             g_stealth_cpuid_cache.rdtsc_exiting_forced);
#endif
}

/*
*   check if a cpuid leaf is out-of-range / invalid on bare metal
*   on bare metal (no hypervisor), leaves in these ranges all return
*   the same default response (usually matching the highest standard leaf):
*/
BOOLEAN
stealth_is_leaf_invalid(UINT32 leaf)
{
    if (!g_stealth_cpuid_cache.initialized)
        return FALSE;

    //
    // hypervisor reserved range — always invalid on bare metal
    //
    if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)
        return TRUE;

    //
    // beyond max standard leaf but below extended range
    //
    if (leaf > g_stealth_cpuid_cache.max_std_leaf && leaf < 0x80000000)
        return TRUE;

    //
    // beyond max extended leaf
    //
    if (leaf >= 0x80000000 && leaf > g_stealth_cpuid_cache.max_ext_leaf)
        return TRUE;

    return FALSE;
}

/*
*   validate a proposed xcr0 value per intel sdm volume 1, section 13.3
*   uses the hardware-supported mask from cpuid.0dh.0 instead of hardcoding
*   which bits are valid — supports pkru, amx, and future extensions
*/
BOOLEAN
stealth_is_xcr0_valid(UINT64 value)
{
    if (g_stealth_cpuid_cache.initialized &&
        (value & ~g_stealth_cpuid_cache.valid_xcr0_mask))
        return FALSE;

    //
    // bit 0 (x87 FPU) must always be set — this is mandatory
    //
    if (!(value & 1ULL))
        return FALSE;

    //
    // if AVX (bit 2) is set, SSE (bit 1) must also be set
    //
    if ((value & 4ULL) && !(value & 2ULL))
        return FALSE;

    //
    // BNDREGS (bit 3) and BNDCSR (bit 4) — must both be set or both clear
    //
    {
        UINT64 mpx_bits = value & 0x18ULL;
        if (mpx_bits != 0 && mpx_bits != 0x18ULL)
            return FALSE;
    }

    //
    // AVX-512 state bits (5=Opmask, 6=ZMM_Hi256, 7=Hi16_ZMM)
    // all three must be set together, and AVX (bit 2) + SSE (bit 1) must be set
    //
    {
        UINT64 avx512_bits = value & 0xE0ULL;
        if (avx512_bits != 0)
        {
            if (avx512_bits != 0xE0ULL)
                return FALSE;

            if (!(value & 6ULL))
                return FALSE;
        }
    }

    //
    // AMX bits (17=XTILECFG, 18=XTILEDATA) — must both be set or both clear
    //
    {
        UINT64 amx_bits = value & 0x60000ULL;
        if (amx_bits != 0 && amx_bits != 0x60000ULL)
            return FALSE;
    }

    return TRUE;
}

