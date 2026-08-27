#pragma once
/*
 * OphionInternal.h — opt-in internal protection helpers.
 *
 * Safe default:
 *   ophion::harden_image(base, size) pins the caller's own image and
 *   registers its pages for per-CR3 execute-only EPT protection.
 *
 * Destructive PEB unlinking, header wiping, game-image pointer patching,
 * and TPM API patches are deliberately not part of the default path.
 * They can break loader/unwind/integrity state and are easier to detect
 * than a manual-mapped image with coherent metadata.
 *
 * External tools must use the physical-memory backend.  Registering a
 * remote CR3 from this header is intentionally unsupported because the
 * kernel must pin pages in the target process context first.
 * Requires a diagnostic Ophion build exposing the protected control device.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>

#define OPHION_IOCTL_PROTECT \
    ((0x22u << 16) | (3u << 14) | (0x803u << 2) | 0u)
#define OPHION_IOCTL_PROTECT_STATUS \
    ((0x22u << 16) | (3u << 14) | (0x804u << 2) | 0u)

#define OPHION_PROTECT_STATUS_AVAILABLE      0x00000001u
#define OPHION_PROTECT_STATUS_MTF            0x00000002u
#define OPHION_PROTECT_STATUS_EXECUTE_ONLY   0x00000004u
#define OPHION_PROTECT_STATUS_PROCESS_NOTIFY 0x00000008u


#define OPHION_PROTECT_FLAG_WHITELIST 0x1u

#pragma pack(push, 1)
struct OphionProtectReq {
    uint64_t OwnerCr3;
    uint64_t GuestVa;
    uint64_t Size;
    uint32_t Flags;
    uint32_t Reserved;
};
struct OphionProtectStatus {
    uint32_t Size;
    uint32_t Version;
    uint32_t Flags;
    uint32_t MaximumPages;
    uint32_t ActiveOwners;
    uint32_t ProtectedPages;
    uint32_t WhitelistRanges;
    uint32_t Reserved;
};

#pragma pack(pop)

#ifdef __cplusplus
extern "C" uint64_t ophion_asm_spoof(void* fn, void* gadget,
                                     uint64_t a0, uint64_t a1);
#endif

namespace ophion {
namespace detail {

inline bool ioctl_protect(uint64_t cr3, void* va, size_t size, uint32_t flags = 0)
{
    HANDLE hv = CreateFileW(L"\\\\.\\Ophion",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hv == INVALID_HANDLE_VALUE)
        return false;
    OphionProtectReq req{};
    req.OwnerCr3 = cr3;
    req.GuestVa  = (uint64_t)va;
    req.Size     = (uint64_t)size;
    req.Flags    = flags;
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(hv, OPHION_IOCTL_PROTECT,
                              &req, sizeof(req), nullptr, 0, &ret, nullptr);
    CloseHandle(hv);
    return ok != FALSE;
}

inline uint8_t* ntdll_text(uint32_t* out_sz)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    auto* dos = (IMAGE_DOS_HEADER*)ntdll;
    auto* nt  = (IMAGE_NT_HEADERS64*)((uint8_t*)ntdll + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    if (out_sz) *out_sz = sec->Misc.VirtualSize;
    return (uint8_t*)ntdll + sec->VirtualAddress;
}

inline void* find_jmp_rbx()
{
    uint32_t sz = 0;
    uint8_t* t = ntdll_text(&sz);
    if (!t) return nullptr;
    for (uint32_t i = 0; i + 2 < sz; i++)
    {
        if (t[i] == 0xFF && t[i + 1] == 0xE3) /* jmp rbx */
            return t + i;
    }
    return nullptr;
}

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL;

inline void unlink_list(LIST_ENTRY* e)
{
    if (!e || !e->Flink || !e->Blink) return;
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
    e->Flink = e;
    e->Blink = e;
}

} // namespace detail

inline bool query_status(OphionProtectStatus* status)
{
    if (!status)
        return false;
    HANDLE hv = CreateFileW(
        L"\\\\.\\Ophion",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hv == INVALID_HANDLE_VALUE)
        return false;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        hv, OPHION_IOCTL_PROTECT_STATUS,
        nullptr, 0,
        status, sizeof(*status),
        &returned, nullptr);
    CloseHandle(hv);
    return ok && returned == sizeof(*status) &&
           status->Size == sizeof(*status) &&
           status->Version == 1;
}

inline bool protect_image(void* base, size_t size)
{
    OphionProtectStatus status{};
    if (!base || !size ||
        !query_status(&status) ||
        !(status.Flags & OPHION_PROTECT_STATUS_AVAILABLE))
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return false;
    }
    return detail::ioctl_protect(0, base, size);
}

inline bool protect_remote(uint64_t, void*, size_t)
{
    SetLastError(ERROR_NOT_SUPPORTED);
    return false;
}

inline bool unlink_module(void* base)
{
    auto* peb = (PEB*)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return false;
    auto* head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* c = head->Flink; c != head; c = c->Flink)
    {
        auto* ldr = CONTAINING_RECORD(c, detail::LDR_DATA_TABLE_ENTRY_FULL,
                                      InMemoryOrderLinks);
        if (ldr->DllBase != base)
            continue;
        detail::unlink_list(&ldr->InLoadOrderLinks);
        detail::unlink_list(&ldr->InMemoryOrderLinks);
        detail::unlink_list(&ldr->InInitializationOrderLinks);
        if (ldr->BaseDllName.Buffer)
            SecureZeroMemory(ldr->BaseDllName.Buffer, ldr->BaseDllName.Length);
        if (ldr->FullDllName.Buffer)
            SecureZeroMemory(ldr->FullDllName.Buffer, ldr->FullDllName.Length);
        return true;
    }
    return false;
}

inline void wipe_headers(void* base)
{
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
    DWORD old = 0;
    SIZE_T hdr = nt->OptionalHeader.SizeOfHeaders;
    if (!hdr) hdr = 0x1000;
    if (VirtualProtect(base, hdr, PAGE_READWRITE, &old))
    {
        SecureZeroMemory(base, hdr);
        VirtualProtect(base, hdr, old, &old);
    }
}

inline void clean_peb()
{
    auto* peb = (PEB*)__readgsqword(0x60);
    if (!peb) return;
    peb->BeingDebugged = 0;
    ((uint8_t*)peb)[0xBC] &= (uint8_t)~0x70; /* NtGlobalFlag low byte */
    *(ULONG*)((uint8_t*)peb + 0xBC) &= ~0x70UL;
}

/*
 * R5AC (drof S25): RtlCaptureSBT is an unchecked .data pointer.
 * Replace every pointer in the main module .data that equals the real
 * RtlCaptureStackBackTrace with a stub that reports 0 frames.
 */
inline unsigned null_sbt_pointers(void* module_base)
{
    static USHORT(NTAPI *real_sbt)(ULONG, ULONG, PVOID, PULONG) =
        (USHORT(NTAPI*)(ULONG, ULONG, PVOID, PULONG))
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCaptureStackBackTrace");

    static USHORT(NTAPI *stub)(ULONG, ULONG, PVOID, PULONG) =
        [](ULONG, ULONG, PVOID, PULONG) -> USHORT { return 0; };

    if (!module_base || !real_sbt) return 0;
    auto* dos = (IMAGE_DOS_HEADER*)module_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)module_base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    unsigned hits = 0;
    for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++)
    {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE))
            continue;
        auto* p = (uint8_t*)module_base + sec->VirtualAddress;
        uint32_t n = sec->Misc.VirtualSize;
        DWORD old = 0;
        if (!VirtualProtect(p, n, PAGE_READWRITE, &old))
            continue;
        for (uint32_t i = 0; i + 8 <= n; i += 8)
        {
            if (*(void**)(p + i) == (void*)real_sbt)
            {
                *(void**)(p + i) = (void*)stub;
                hits++;
            }
        }
        VirtualProtect(p, n, old, &old);
    }
    return hits;
}

enum HardenOption : uint32_t {
    HardenNone          = 0,
    HardenUnlinkPeb     = 1u << 0,
    HardenWipeHeaders   = 1u << 1,
    HardenNullR5Capture = 1u << 2,
    HardenCleanPeb      = 1u << 3
};

inline bool allow_caller_module(HMODULE module)
{
    if (!module)
        return false;
    auto* dos = (IMAGE_DOS_HEADER*)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    return detail::ioctl_protect(
        0, module, nt->OptionalHeader.SizeOfImage,
        OPHION_PROTECT_FLAG_WHITELIST);
}

inline bool harden_image_ex(void* base, size_t size, uint32_t options)
{
    if (!protect_image(base, size))
        return false;
    if (options & HardenCleanPeb)
        clean_peb();
    if (options & HardenUnlinkPeb)
        unlink_module(base);
    if (options & HardenWipeHeaders)
        wipe_headers(base);
    if (options & HardenNullR5Capture)
        null_sbt_pointers(GetModuleHandleW(nullptr));
    return true;
}

inline bool harden_image(void* base, size_t size)
{
    return harden_image_ex(base, size, HardenNone);
}

#ifdef __cplusplus
inline uint64_t spoof(void* fn, uint64_t a0 = 0, uint64_t a1 = 0)
{
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY cet{};
    static void* gadget;

    if (GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessUserShadowStackPolicy,
            &cet, sizeof(cet)) &&
        cet.EnableUserShadowStack)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }
    if (!gadget)
        gadget = detail::find_jmp_rbx();
    if (!gadget || !fn)
        return 0;
    return ophion_asm_spoof(fn, gadget, a0, a1);
}
#endif

} // namespace ophion
