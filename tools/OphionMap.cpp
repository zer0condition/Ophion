#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "../include/hv_public.h"
#include "../include/hv_transport_mac.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>

#include <fstream>
#include <string>
#include <vector>

namespace {

struct Reloc {
    std::uint64_t rva;
    std::uint16_t type;
};

std::vector<std::uint8_t> readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot read " + path);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void writeFile(const std::string& path, const void* data, std::size_t size) {
    std::ofstream out(path, std::ios::binary);
    if (!out)
        throw std::runtime_error("cannot write " + path);
    out.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
}

PIMAGE_NT_HEADERS64 ntHeaders(std::uint8_t* base, std::size_t fileSize) {
    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("PE file is truncated");
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error("not a PE");
    if (dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
            fileSize)
        throw std::runtime_error("NT headers out of file bounds");
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error("not a PE32+ image");
    return nt;
}

std::uint32_t rvaToOffset(PIMAGE_NT_HEADERS64 nt, std::uint32_t rva,
                          std::size_t fileSize) {
    auto* section = IMAGE_FIRST_SECTION(nt);
    if (!nt->FileHeader.NumberOfSections ||
        nt->FileHeader.NumberOfSections > 96)
        throw std::runtime_error("implausible section count");
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress &&
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            auto offset = static_cast<std::uint64_t>(
                static_cast<std::uint64_t>(section->PointerToRawData) +
                (rva - section->VirtualAddress));
            if (offset >= fileSize)
                throw std::runtime_error("RVA resolves outside the file");
            return static_cast<std::uint32_t>(offset);
        }
    }
    throw std::runtime_error("RVA not in a section");
}

std::uint32_t findSharedPageRva(PIMAGE_NT_HEADERS64 nt) {
    static constexpr char kName[IMAGE_SIZEOF_SHORT_NAME] = {
        '.', 'h', 'v', 's', 'h', 'a', 'r', 'e'
    };
    PIMAGE_SECTION_HEADER match = nullptr;
    auto* section = IMAGE_FIRST_SECTION(nt);

    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (std::memcmp(section->Name, kName, sizeof(kName)) != 0)
            continue;
        if (match)
            throw std::runtime_error("duplicate .hvshare sections");
        match = section;
    }
    if (!match)
        throw std::runtime_error("missing .hvshare command page");
    if ((match->VirtualAddress & 0xFFFu) != 0 ||
        match->Misc.VirtualSize < 4096)
        throw std::runtime_error(".hvshare must be page aligned and 4096 bytes");
    if ((match->Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
        (match->Characteristics & IMAGE_SCN_MEM_WRITE) == 0 ||
        (match->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        throw std::runtime_error(".hvshare must be RW and NX");
    return match->VirtualAddress;
}

std::vector<std::uint8_t> mapImage(std::uint8_t* file, PIMAGE_NT_HEADERS64 nt,
                                   std::size_t fileSize) {
    if (!nt->OptionalHeader.SizeOfImage ||
        nt->OptionalHeader.SizeOfHeaders > fileSize ||
        nt->OptionalHeader.SizeOfHeaders > nt->OptionalHeader.SizeOfImage)
        throw std::runtime_error("invalid PE image/header size");
    std::vector<std::uint8_t> image(nt->OptionalHeader.SizeOfImage, 0);
    std::memcpy(image.data(), file, nt->OptionalHeader.SizeOfHeaders);
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (!section->SizeOfRawData)
            continue;
        if (static_cast<std::uint64_t>(section->PointerToRawData) +
                section->SizeOfRawData >
            fileSize)
            throw std::runtime_error("section raw data escapes file");
        if (static_cast<std::uint64_t>(section->VirtualAddress) +
                section->SizeOfRawData >
            image.size())
            throw std::runtime_error("section overflows image");
        std::memcpy(image.data() + section->VirtualAddress,
                    file + section->PointerToRawData,
                    section->SizeOfRawData);
    }
    return image;
}

std::vector<Reloc> collectRelocs(std::uint8_t* file, PIMAGE_NT_HEADERS64 nt,
                                 std::size_t fileSize) {
    std::vector<Reloc> relocs;
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size)
        return relocs;
    auto directoryOffset = rvaToOffset(nt, dir.VirtualAddress, fileSize);
    if (dir.Size > fileSize - directoryOffset)
        throw std::runtime_error("relocation directory escapes file");
    auto* block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        file + directoryOffset);
    auto* end = reinterpret_cast<std::uint8_t*>(block) + dir.Size;
    while (reinterpret_cast<std::uint8_t*>(block) < end && block->SizeOfBlock) {
        if (static_cast<std::size_t>(reinterpret_cast<std::uint8_t*>(block) -
                                     file) +
                block->SizeOfBlock >
            fileSize)
            throw std::runtime_error("relocation block out of bounds");
        unsigned count =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        auto* entries = reinterpret_cast<std::uint16_t*>(block + 1);
        for (unsigned i = 0; i < count; i++) {
            Reloc reloc{};
            reloc.type = entries[i] >> 12;
            reloc.rva = block->VirtualAddress + (entries[i] & 0xFFF);
            if (reloc.type != IMAGE_REL_BASED_ABSOLUTE)
                relocs.push_back(reloc);
        }
        block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
    }
    return relocs;
}

void applyRelocs(std::uint8_t* image, PIMAGE_NT_HEADERS64 nt,
                 const std::vector<Reloc>& relocs, std::uint64_t newBase) {
    auto delta = static_cast<std::int64_t>(newBase - nt->OptionalHeader.ImageBase);
    for (const auto& reloc : relocs) {
        if (reloc.type != IMAGE_REL_BASED_DIR64)
            throw std::runtime_error("unsupported reloc type");
        auto* slot = reinterpret_cast<std::uint64_t*>(image + reloc.rva);
        *slot = static_cast<std::uint64_t>(static_cast<std::int64_t>(*slot) + delta);
    }
}

std::uint32_t exportRva(std::uint8_t* file, PIMAGE_NT_HEADERS64 nt,
                        const char* name, std::size_t fileSize) {
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
        throw std::runtime_error("no export directory");
    auto* exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        file + rvaToOffset(nt, dir.VirtualAddress, fileSize));
    auto* names = reinterpret_cast<std::uint32_t*>(
        file + rvaToOffset(nt, exp->AddressOfNames, fileSize));
    auto* ords = reinterpret_cast<std::uint16_t*>(
        file + rvaToOffset(nt, exp->AddressOfNameOrdinals, fileSize));
    auto* funcs = reinterpret_cast<std::uint32_t*>(
        file + rvaToOffset(nt, exp->AddressOfFunctions, fileSize));
    for (std::uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* exportName =
            reinterpret_cast<const char*>(file + rvaToOffset(nt, names[i], fileSize));
        if (std::strcmp(exportName, name) == 0)
            return funcs[ords[i]];
    }
    throw std::runtime_error(std::string("export not found: ") + name);
}

void resolveImports(std::uint8_t* image, PIMAGE_NT_HEADERS64 mappedNt,
                    std::uint8_t* ntosFile, PIMAGE_NT_HEADERS64 ntosNt,
                    std::size_t ntosFileSize, std::uint64_t ntosBase) {
    auto& dir = mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return;
    auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image + dir.VirtualAddress);
    for (; desc->Name; desc++) {
        const char* module = reinterpret_cast<const char*>(image + desc->Name);
        if (_stricmp(module, "ntoskrnl.exe") != 0 &&
            _stricmp(module, "hal.dll") != 0 &&
            _stricmp(module, "ntoskrnl") != 0)
            throw std::runtime_error(std::string("unsupported import module ") + module);
        auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(
            image + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        auto* iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(image + desc->FirstThunk);
        for (; thunk->u1.AddressOfData; thunk++, iat++) {
            if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal))
                throw std::runtime_error("ordinal imports are not supported");
            auto* byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                image + thunk->u1.AddressOfData);
            auto rva = exportRva(ntosFile, ntosNt,
                                 reinterpret_cast<const char*>(byName->Name),
                                 ntosFileSize);
            iat->u1.Function = ntosBase + rva;
        }
    }
}

std::vector<std::uint8_t> buildEntryThunk(std::uint64_t entryVa) {
    /*
     * Microsoft x64 ABI adapter for write/execute primitives that invoke a
     * zero-argument kernel callback.  The production DriverEntry ignores both
     * arguments; this thunk supplies NULLs, reserves shadow space, calls the
     * relocated entry VA, and returns its NTSTATUS in RAX.
     */
    std::vector<std::uint8_t> thunk = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 28h
        0x31, 0xC9,                         // xor ecx, ecx
        0x31, 0xD2,                         // xor edx, edx
        0x48, 0xB8,                         // mov rax, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 28h
        0xC3                                // ret
    };
    std::memcpy(thunk.data() + 10, &entryVa, sizeof(entryVa));
    return thunk;
}

constexpr std::size_t kStopCapabilityLowOffset = 39;
constexpr std::size_t kStopCapabilityHighOffset = 49;
constexpr std::size_t kStopEpochOffset = 59;

std::vector<std::uint8_t>
buildAuthenticatedVmcallThunk(std::uint32_t command) {
    /*
     * Per-CPU authenticated VMXOFF doorbell.  The runtime patches only the
     * capability and epoch slots described in the manifest, then schedules
     * this thunk synchronously on every logical processor.
     */
    std::vector<std::uint8_t> thunk = {
        0x41, 0x54,                         // push r12
        0x49, 0xBA,                         // mov r10, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0xBB,                         // mov r11, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0xBC,                         // mov r12, imm64
        0, 0, 0, 0, 0, 0, 0, 0,
        0xB9, 0, 0, 0, 0,                  // mov ecx, imm32
        0x48, 0xBA,                         // mov rdx, capability low
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0xB8,                         // mov r8, capability high
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0xB9,                         // mov r9, epoch
        0, 0, 0, 0, 0, 0, 0, 0,
        0x0F, 0x01, 0xC1,                  // vmcall
        0x41, 0x5C,                         // pop r12
        0xC3                                // ret
    };
    const std::uint64_t frameR10 = HV_VMCALL_FRAME_R10;
    const std::uint64_t frameR11 = HV_VMCALL_FRAME_R11;
    const std::uint64_t frameR12 = HV_VMCALL_FRAME_R12;

    std::memcpy(thunk.data() + 4, &frameR10, sizeof(frameR10));
    std::memcpy(thunk.data() + 14, &frameR11, sizeof(frameR11));
    std::memcpy(thunk.data() + 24, &frameR12, sizeof(frameR12));
    std::memcpy(thunk.data() + 33, &command, sizeof(command));
    return thunk;
}

std::vector<std::uint8_t> buildStopThunk() {
    return buildAuthenticatedVmcallThunk(
        HV_ROOT_VMCALL_STOP_STEP);
}

std::vector<std::uint8_t> buildBootstrapThunk() {
    return buildAuthenticatedVmcallThunk(
        HV_ROOT_VMCALL_BOOTSTRAP_STEP);
}

std::vector<std::uint8_t> buildSealThunk() {
    return buildAuthenticatedVmcallThunk(
        HV_ROOT_VMCALL_SEAL_STEP);
}

bool runMacSelfTest() {
    constexpr std::uint64_t keyLow = 0x0706050403020100ULL;
    constexpr std::uint64_t keyHigh = 0x0F0E0D0C0B0A0908ULL;
    std::uint8_t payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    HV_TRANSPORT_SIPHASH sip{};
    std::uint64_t requestLow = 0;
    std::uint64_t requestHigh = 0;
    std::uint64_t repeatLow = 0;
    std::uint64_t repeatHigh = 0;
    std::uint64_t changedLow = 0;
    std::uint64_t changedHigh = 0;
    std::uint64_t responseLow = 0;
    std::uint64_t responseHigh = 0;

    hv_transport_sip_init(&sip, keyLow, keyHigh);
    if (hv_transport_sip_finish(&sip) != 0x726FDB47DD0E0E31ULL)
        return false;

    hv_transport_mac_request(
        keyLow, keyHigh, 2, 7, 11,
        sizeof(payload), 112, payload,
        &requestLow, &requestHigh);
    hv_transport_mac_request(
        keyLow, keyHigh, 2, 7, 11,
        sizeof(payload), 112, payload,
        &repeatLow, &repeatHigh);
    payload[2] ^= 1;
    hv_transport_mac_request(
        keyLow, keyHigh, 2, 7, 11,
        sizeof(payload), 112, payload,
        &changedLow, &changedHigh);
    payload[2] ^= 1;
    hv_transport_mac_response(
        keyLow, keyHigh, 2, 7, 11,
        0, sizeof(payload), payload,
        &responseLow, &responseHigh);

    auto requestDiffers = [&](std::uint64_t candidateKeyLow,
                              std::uint64_t candidateKeyHigh,
                              std::uint32_t command,
                              std::uint64_t epoch,
                              std::uint64_t sequence,
                              std::uint32_t requestBytes,
                              std::uint32_t responseCapacity) {
        std::uint64_t low = 0;
        std::uint64_t high = 0;
        hv_transport_mac_request(
            candidateKeyLow, candidateKeyHigh,
            command, epoch, sequence,
            requestBytes, responseCapacity, payload,
            &low, &high);
        return low != requestLow || high != requestHigh;
    };

    return requestLow == repeatLow &&
           requestHigh == repeatHigh &&
           (requestLow != changedLow ||
            requestHigh != changedHigh) &&
           (requestLow != responseLow ||
            requestHigh != responseHigh) &&
           requestDiffers(keyLow ^ 1, keyHigh, 2, 7, 11, 5, 112) &&
           requestDiffers(keyLow, keyHigh ^ 1, 2, 7, 11, 5, 112) &&
           requestDiffers(keyLow, keyHigh, 3, 7, 11, 5, 112) &&
           requestDiffers(keyLow, keyHigh, 2, 8, 11, 5, 112) &&
           requestDiffers(keyLow, keyHigh, 2, 7, 12, 5, 112) &&
           requestDiffers(keyLow, keyHigh, 2, 7, 11, 4, 112) &&
           requestDiffers(keyLow, keyHigh, 2, 7, 11, 5, 113);
}

void usage() {
    std::fputs(
        "OphionMap — relocate a production .sys without sc.exe / NtLoadDriver\n"
        "usage: OphionMap.exe --image <Ophion-production.sys> --out <dir>\n"
        "                    --base <hex kernel VA> --ntos <ntoskrnl.exe>\n"
        "                    --ntos-base <hex>\n"
        "       OphionMap.exe --mac-self-test\n"
        "emits ophion.map.bin, ophion.exec.bin, ophion.bootstrap.bin,\n"
        "      ophion.seal.bin, ophion.stop.bin, ophion.cleanup.bin,\n"
        "      and ophion.map.json\n"
        "copy the image and thunk with an external kernel write/execute primitive\n",
        stderr);
}

std::uint64_t parseHexStrict(
    const std::string& text,
    const char* option) {
    char* end = nullptr;
    std::uint64_t value;

    if (text.empty() || text[0] == '-' || text[0] == '+' ||
        text.find_first_of(" \t\r\n") != std::string::npos)
        throw std::runtime_error(
            std::string("invalid numeric value for ") + option);
    errno = 0;
    value = std::strtoull(text.c_str(), &end, 0);
    if (errno == ERANGE || end == text.c_str() || !end || *end != '\0')
        throw std::runtime_error(
            std::string("invalid numeric value for ") + option);
    return value;
}

bool isCanonicalKernelVa(std::uint64_t address) {
    const bool canonical48 =
        ((address >> 47) & 1ULL) != 0 &&
        (address >> 48) == 0xFFFFULL;
    const bool canonical57 =
        ((address >> 56) & 1ULL) != 0 &&
        (address >> 57) == 0x7FULL;
    return canonical48 || canonical57;
}

void validatePlacement(
    PIMAGE_NT_HEADERS64 nt,
    std::uint64_t base,
    const char* label,
    bool requireSectionAlignment) {
    std::uint64_t alignment = requireSectionAlignment
        ? nt->OptionalHeader.SectionAlignment
        : 0x1000ULL;
    const std::uint64_t imageSize =
        nt->OptionalHeader.SizeOfImage;

    if (alignment < 0x1000ULL)
        alignment = 0x1000ULL;
    if (!base || !isCanonicalKernelVa(base))
        throw std::runtime_error(
            std::string(label) +
            " base must be a canonical kernel VA");
    if ((base % alignment) != 0)
        throw std::runtime_error(
            std::string(label) +
            " base must be aligned to PE SectionAlignment");
    if (!imageSize ||
        base >
            (std::numeric_limits<std::uint64_t>::max)() - imageSize)
        throw std::runtime_error(
            std::string(label) + " image range overflows");
}

void validateEntryPoint(PIMAGE_NT_HEADERS64 nt) {
    const std::uint32_t entryRva =
        nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRva >= nt->OptionalHeader.SizeOfImage)
        throw std::runtime_error(
            "entry point is outside the mapped image");

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections;
         i++, section++) {
        const std::uint32_t sectionSize =
            section->Misc.VirtualSize > section->SizeOfRawData
                ? section->Misc.VirtualSize
                : section->SizeOfRawData;
        const std::uint64_t sectionEnd =
            static_cast<std::uint64_t>(section->VirtualAddress) +
            sectionSize;
        if (entryRva < section->VirtualAddress ||
            entryRva >= sectionEnd)
            continue;
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
            throw std::runtime_error(
                "entry point is not in an executable section");
        return;
    }
    throw std::runtime_error(
        "entry point is not in a mapped section");
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string imagePath;
        std::string outDir = ".";
        std::string ntosPath;
        std::uint64_t base = 0;
        std::uint64_t ntosBase = 0;
        bool haveBase = false;
        bool macSelfTest = false;

        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            auto need = [&](const char* name) -> std::string {
                if (i + 1 >= argc)
                    throw std::runtime_error(std::string("missing value for ") + name);
                return argv[++i];
            };
            if (arg == "--image")
                imagePath = need("--image");
            else if (arg == "--out")
                outDir = need("--out");
            else if (arg == "--base") {
                base = parseHexStrict(need("--base"), "--base");
                haveBase = true;
            } else if (arg == "--ntos")
                ntosPath = need("--ntos");
            else if (arg == "--ntos-base")
                ntosBase = parseHexStrict(
                    need("--ntos-base"), "--ntos-base");
            else if (arg == "--mac-self-test")
                macSelfTest = true;
            else if (arg == "--help" || arg == "-h") {
                usage();
                return 0;
            } else
                throw std::runtime_error("unknown argument " + arg);
        }
        if (macSelfTest) {
            if (!runMacSelfTest())
                throw std::runtime_error("transport MAC self-test failed");
            std::puts("Transport MAC self-test passed");
            return 0;
        }
        if (imagePath.empty()) {
            usage();
            return 2;
        }
        if (!haveBase)
            throw std::runtime_error("--base is required for a launchable artifact");
        if (ntosPath.empty() || !ntosBase)
            throw std::runtime_error(
                "--ntos and --ntos-base are required for a launchable artifact");

        auto file = readFile(imagePath);
        auto* nt = ntHeaders(file.data(), file.size());
        validatePlacement(nt, base, "mapped", true);
        validateEntryPoint(nt);
        auto sharedPageRva = findSharedPageRva(nt);
        auto cleanupRva = exportRva(
            file.data(), nt, "OphionCleanup", file.size());
        auto image = mapImage(file.data(), nt, file.size());
        auto* mappedNt = ntHeaders(image.data(), image.size());
        auto relocs = collectRelocs(file.data(), nt, file.size());
        applyRelocs(image.data(), mappedNt, relocs, base);

        auto ntosFile = readFile(ntosPath);
        auto* ntosNt = ntHeaders(ntosFile.data(), ntosFile.size());
        validatePlacement(ntosNt, ntosBase, "ntos", false);
        resolveImports(image.data(), mappedNt, ntosFile.data(), ntosNt,
                       ntosFile.size(), ntosBase);

        auto entryVa = base + mappedNt->OptionalHeader.AddressOfEntryPoint;
        auto cleanupVa = base + cleanupRva;
        auto entryThunk = buildEntryThunk(entryVa);
        auto bootstrapThunk = buildBootstrapThunk();
        auto sealThunk = buildSealThunk();
        auto cleanupThunk = buildEntryThunk(cleanupVa);
        auto stopThunk = buildStopThunk();

        CreateDirectoryA(outDir.c_str(), nullptr);
        auto binPath = outDir + "\\ophion.map.bin";
        auto thunkPath = outDir + "\\ophion.exec.bin";
        auto bootstrapPath = outDir + "\\ophion.bootstrap.bin";
        auto sealPath = outDir + "\\ophion.seal.bin";
        auto stopPath = outDir + "\\ophion.stop.bin";
        auto cleanupPath = outDir + "\\ophion.cleanup.bin";
        auto jsonPath = outDir + "\\ophion.map.json";
        writeFile(binPath, image.data(), image.size());
        writeFile(thunkPath, entryThunk.data(), entryThunk.size());
        writeFile(
            bootstrapPath,
            bootstrapThunk.data(),
            bootstrapThunk.size());
        writeFile(sealPath, sealThunk.data(), sealThunk.size());
        writeFile(stopPath, stopThunk.data(), stopThunk.size());
        writeFile(cleanupPath, cleanupThunk.data(), cleanupThunk.size());

        std::ofstream json(jsonPath);
        json << "{\n";
        json << "  \"schema\": \"ophion.map.v2\",\n";
        json << "  \"abiVersion\": 1,\n";
        json << "  \"entryRva\": " << mappedNt->OptionalHeader.AddressOfEntryPoint << ",\n";
        json << "  \"entryVa\": \"0x" << std::hex << entryVa << std::dec << "\",\n";
        json << "  \"cleanupRva\": " << cleanupRva << ",\n";
        json << "  \"cleanupVa\": \"0x" << std::hex << cleanupVa << std::dec << "\",\n";
        json << "  \"size\": " << image.size() << ",\n";
        json << "  \"preferredBase\": \"0x" << std::hex << mappedNt->OptionalHeader.ImageBase
             << std::dec << "\",\n";
        json << "  \"relocatedBase\": \"0x" << std::hex << base << std::dec << "\"";
        json << ",\n  \"relocCount\": " << relocs.size() << ",\n";
        json << "  \"importsResolved\": true,\n";
        json << "  \"executionThunk\": \"ophion.exec.bin\",\n";
        json << "  \"executionThunkSize\": " << entryThunk.size() << ",\n";
        json << "  \"bootstrapThunk\": \"ophion.bootstrap.bin\",\n";
        json << "  \"bootstrapThunkSize\": " << bootstrapThunk.size() << ",\n";
        json << "  \"bootstrapCapabilityLowOffset\": "
             << kStopCapabilityLowOffset << ",\n";
        json << "  \"bootstrapCapabilityHighOffset\": "
             << kStopCapabilityHighOffset << ",\n";
        json << "  \"bootstrapEpochOffset\": " << kStopEpochOffset << ",\n";
        json << "  \"sealThunk\": \"ophion.seal.bin\",\n";
        json << "  \"sealThunkSize\": " << sealThunk.size() << ",\n";
        json << "  \"sealCapabilityLowOffset\": "
             << kStopCapabilityLowOffset << ",\n";
        json << "  \"sealCapabilityHighOffset\": "
             << kStopCapabilityHighOffset << ",\n";
        json << "  \"sealEpochOffset\": " << kStopEpochOffset << ",\n";
        json << "  \"stopThunk\": \"ophion.stop.bin\",\n";
        json << "  \"stopThunkSize\": " << stopThunk.size() << ",\n";
        json << "  \"stopCapabilityLowOffset\": "
             << kStopCapabilityLowOffset << ",\n";
        json << "  \"stopCapabilityHighOffset\": "
             << kStopCapabilityHighOffset << ",\n";
        json << "  \"stopEpochOffset\": " << kStopEpochOffset << ",\n";
        json << "  \"cleanupThunk\": \"ophion.cleanup.bin\",\n";
        json << "  \"cleanupThunkSize\": " << cleanupThunk.size() << ",\n";
        json << "  \"sharedPageRva\": " << sharedPageRva << ",\n";
        json << "  \"commandMagic\": \"0x" << std::hex
             << HV_ROOT_COMMAND_MAGIC << std::dec << "\",\n";
        json << "  \"commandVersion\": " << HV_ROOT_COMMAND_VERSION_1 << ",\n";
        json << "  \"commandHeaderBytes\": " << HV_ROOT_COMMAND_HEADER_BYTES << ",\n";
        json << "  \"commandPageBytes\": " << HV_ROOT_COMMAND_PAGE_BYTES << ",\n";
        json << "  \"macAlgorithm\": \"" << HV_TRANSPORT_MAC_ALGORITHM << "\",\n";
        json << "  \"recordMacOffset\": "
             << FIELD_OFFSET(HV_ROOT_COMMAND_PAGE_V1, RecordMacLow) << ",\n";
        json << "  \"recordMacBytes\": 16,\n";
        json << "  \"bootstrapState\": " << HV_ROOT_STATE_WRITING << ",\n";
        json << "  \"bootstrapRequestBytes\": "
             << sizeof(HV_ROOT_BOOTSTRAP_V1) << ",\n";
        json << "  \"capabilityPayloadOffset\": "
             << FIELD_OFFSET(HV_ROOT_COMMAND_PAGE_V1, Payload) << ",\n";
        json << "  \"initialSequence\": 1,\n";
        json << "  \"vmcallFrameR10\": \"0x" << std::hex
             << HV_VMCALL_FRAME_R10 << std::dec << "\",\n";
        json << "  \"vmcallFrameR11\": \"0x" << std::hex
             << HV_VMCALL_FRAME_R11 << std::dec << "\",\n";
        json << "  \"vmcallFrameR12\": \"0x" << std::hex
             << HV_VMCALL_FRAME_R12 << std::dec << "\",\n";
        json << "  \"sealVmcallStep\": " << HV_ROOT_VMCALL_SEAL_STEP << ",\n";
        json << "  \"stopVmcallStep\": " << HV_ROOT_VMCALL_STOP_STEP << ",\n";
        json << "  \"bootstrapVmcallStep\": "
             << HV_ROOT_VMCALL_BOOTSTRAP_STEP << ",\n";
        json << "  \"rootCommandVmcall\": " << HV_ROOT_VMCALL_COMMAND << ",\n";
        json << "  \"requiresRootBootstrap\": true,\n";
        json << "  \"bootstrapAfterEntry\": true,\n";
        json << "  \"requiresAllCoreSeal\": true,\n";
        json << "  \"requiresAllCoreStop\": true,\n";
        json << "  \"loader\": \"none-sc-none-ntloaddriver\"\n";
        json << "}\n";
        std::printf(
                    "wrote %s (%zu), %s (%zu), %s (%zu), %s (%zu), "
                    "%s (%zu), %s (%zu), and %s\n",
                    binPath.c_str(), image.size(), thunkPath.c_str(),
                    entryThunk.size(), bootstrapPath.c_str(),
                    bootstrapThunk.size(), sealPath.c_str(), sealThunk.size(),
                    stopPath.c_str(), stopThunk.size(),
                    cleanupPath.c_str(), cleanupThunk.size(),
                    jsonPath.c_str());
        return 0;
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "OphionMap: %s\n", ex.what());
        return 1;
    }
}
