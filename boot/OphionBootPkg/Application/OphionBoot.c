/*
 * OphionBoot.c - UEFI application entry.
 *
 * Registers a ReadyToBoot callback; when the firmware signals ReadyToBoot,
 * virtualizes the BSP and every AP via EFI_MP_SERVICES_PROTOCOL, then
 * returns control. From that point the boot chain and Windows run as guest
 * under the Hyper-V persona.
 */

#include "OphionBoot.h"
#include <Pi/PiMultiPhase.h>
#include <Protocol/MpService.h>
#include <Library/UefiLib.h>
#include <Register/Intel/ArchitecturalMsr.h>

OPB_VCPU g_opb_vcpu[OPB_MAX_PROCESSORS];
UINT32 g_opb_cpu_count = 0;

STATIC EFI_MP_SERVICES_PROTOCOL *m_MpServices = NULL;
STATIC EFI_EVENT m_ReadyToBootEvent = NULL;
STATIC volatile UINT32 m_CoresVirtualized = 0;
STATIC volatile UINT32 m_CoresFailed = 0;

#define OPB_SHUTDOWN_KEY 0x4E4F485950455256ULL /* 'NOHYPERV' in R12 */

STATIC
VOID
EFIAPI
OpbVirtualizeAp (
    IN OUT VOID *ProcedureArgument
    )
{
    EFI_STATUS Status;
    UINT32 CoreIndex = (UINT32)(UINTN)ProcedureArgument;

    Status = OpbAsmSaveAndVirtualize (CoreIndex);
    if (EFI_ERROR (Status)) {
        m_CoresFailed++;
        return;
    }
    /* AP returns to the firmware MP wait loop non-root */
    m_CoresVirtualized++;
}

STATIC
VOID
EFIAPI
OpbReadyToBootCallback (
    IN EFI_EVENT Event,
    IN VOID *Context
    )
{
    EFI_STATUS Status;
    UINT32 ApIndex;
    UINTN BspContext = 0;

    if (Event != NULL) {
        gBS->CloseEvent (Event);
    }

    Status = gBS->LocateProtocol (&gEfiMpServiceProtocolGuid, NULL,
                                  (VOID **)&m_MpServices);
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "OphionBoot: no MP services - aborting\n"));
        return;
    }

    /* BSP bring-up; successful VMLAUNCH returns here non-root. */
    Status = OpbAsmSaveAndVirtualize (0);
    if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "OphionBoot: BSP virtualization failed %r\n", Status));
        return;
    }
    m_CoresVirtualized++;

    /* AP bring-up: each AP returns to the firmware MP wait loop non-root. */
    for (ApIndex = 1; ApIndex < g_opb_cpu_count; ApIndex++) {
        Status = m_MpServices->StartupThisAP (
                     m_MpServices,
                     OpbVirtualizeAp,
                     ApIndex,
                     NULL,
                     0,
                     (VOID *)(UINTN)ApIndex,
                     NULL
                     );
        if (EFI_ERROR (Status)) {
            m_CoresFailed++;
        }
    }

    DEBUG ((DEBUG_INFO,
            "OphionBoot: %u cores virtualized, %u failed\n",
            m_CoresVirtualized, m_CoresFailed));
    (VOID)BspContext;
}

EFI_STATUS
EFIAPI
OphionBootEntry (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable
    )
{
    EFI_STATUS Status;

    (VOID)ImageHandle;
    (VOID)SystemTable;

    OpbTelemetryInitialize ();

    Status = gBS->LocateProtocol (&gEfiMpServiceProtocolGuid, NULL,
                                  (VOID **)&m_MpServices);
    if (EFI_ERROR (Status)) {
        return Status;
    }
    {
        UINTN Total;
        UINTN Enabled;

        Status = m_MpServices->GetNumberOfProcessors (
                                 m_MpServices, &Total, &Enabled);
        if (EFI_ERROR (Status) || Total == 0) {
            return EFI_UNSUPPORTED;
        }
        g_opb_cpu_count = (UINT32)(Total > OPB_MAX_PROCESSORS
                                    ? OPB_MAX_PROCESSORS : Total);
    }

    /*
     * DXE drivers remain resident after their entry point returns. Start
     * VMX only at ReadyToBoot, after the firmware stack is initialized but
     * before the boot manager transfers to winload.
     */
    Status = gBS->CreateEventEx (
                    EVT_NOTIFY_SIGNAL,
                    TPL_CALLBACK,
                    OpbReadyToBootCallback,
                    NULL,
                    &gEfiEventReadyToBootGuid,
                    &m_ReadyToBootEvent
                    );
    return Status;
}
