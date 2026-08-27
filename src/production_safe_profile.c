/*
 * production_safe_profile.c - inert replacements for research-only mutation
 * modules that are structurally excluded from the production link.
 */
#include "hv.h"

#if !OPHION_PRODUCTION
#error production_safe_profile.c is production-only
#endif

VOID tracewipe_apply(PDRIVER_OBJECT driver_obj, BOOLEAN preserve_dispatch)
{
    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(preserve_dispatch);
}

VOID eac_stealth_apply(VOID)
{
}

VOID eac_stack_scrub(VOID)
{
}

VOID eac_stealth_query(PULONG flags, PULONG counters)
{
    if (flags)
        *flags = 0;
    if (counters)
        RtlZeroMemory(counters, 3 * sizeof(*counters));
}

NTSTATUS byovd_conceal_driver(
    const UNICODE_STRING * driver_name,
    BOOLEAN wipe_ldr)
{
    UNREFERENCED_PARAMETER(driver_name);
    UNREFERENCED_PARAMETER(wipe_ldr);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS byovd_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io_stack)
{
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(io_stack);
    return STATUS_NOT_SUPPORTED;
}