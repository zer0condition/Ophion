## @file
# OphionBootPkg.dsc
# Platform description building the resident OphionBoot DXE driver.
#
# Build (from an edk2 checkout with BaseTools ready):
#   set NASM_PREFIX=<nasm dir>\
#   edksetup.bat
#   build -t VS2022 -a X64 -p OphionBootPkg\OphionBootPkg.dsc -b NOOPT
#
# Copyright (c) 2026 NetVar1337. MIT licensed.
##

[Defines]
  PLATFORM_NAME                  = OphionBoot
  PLATFORM_GUID                  = 2C5B8D30-71AE-4C64-9B0F-1E7A6D93C4B5
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/OphionBoot
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = NOOPT|DEBUG|RELEASE

[LibraryClasses]

  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  DevicePathLibDevicePathProtocol|MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
  UefiDevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib|MdePkg/Library/UefiDebugLibStdErr/UefiDebugLibStdErr.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

[Components]
  OphionBootPkg/Application/OphionBoot.inf

[PcdsFixedAtBuild]
  gOphionBootPkgTokenSpaceGuid.OphionBootMaxProcessors|64

  gOphionBootPkgTokenSpaceGuid.OphionBootConcealRuntime|TRUE