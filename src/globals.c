/*
*   globals.c - global variable definitions
*/
#include "hv.h"

VIRTUAL_MACHINE_STATE *g_vcpu               = NULL;
EPT_STATE *g_ept                            = NULL;
UINT32 g_cpu_count                          = 0;
UINT64 g_system_cr3                         = 0;
UINT64 *g_msr_bitmap_invalid                = NULL;
HOST_IDT_STATE g_host_idt                   = {0};
volatile LONG g_host_nmi_pending[MAX_PROCESSORS] = {0};

BOOLEAN g_stealth_enabled                   = STEALTH_ENABLED;
STEALTH_CPUID_CACHE g_stealth_cpuid_cache   = {0};
