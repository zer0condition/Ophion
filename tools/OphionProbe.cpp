#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "hv_public.h"

namespace {
constexpr unsigned kDefaultSamples = 256;

struct CpuidResult { std::uint32_t eax, ebx, ecx, edx; };
struct TimingSample { std::uint64_t tscDelta; std::int64_t qpcDelta; };
struct ProcessorResult {
    WORD group;
    BYTE number;
    DWORD pinError = ERROR_SUCCESS;
    CpuidResult leaf1{}, hypervisorBase{}, hypervisorInterface{}, invalidFixed{}, invalidMaxPlusOne{};
    std::vector<std::pair<std::uint32_t, CpuidResult>> hypervisorLeaves;
    std::vector<TimingSample> samples;
};
struct DriverStatus {
    enum class Format { Unavailable, Legacy, V1 } format = Format::Unavailable;
    DWORD error = ERROR_SUCCESS;
    std::uint32_t legacyProcessors = 0;
    HV_STATUS_V1 v1{};
};

CpuidResult cpuid(std::uint32_t leaf, std::uint32_t subleaf = 0) {
    int r[4]{};
    __cpuidex(r, static_cast<int>(leaf), static_cast<int>(subleaf));
    return {static_cast<std::uint32_t>(r[0]), static_cast<std::uint32_t>(r[1]),
            static_cast<std::uint32_t>(r[2]), static_cast<std::uint32_t>(r[3])};
}

std::string jsonString(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (ch < 0x20) {
                static constexpr char hex[] = "0123456789abcdef";
                out << "\\u00" << hex[ch >> 4] << hex[ch & 0xf];
            } else out << static_cast<char>(ch);
        }
    }
    out << '"';
    return out.str();
}

std::string fixedString(const char* value, std::size_t capacity) {
    std::size_t length = 0;
    while (length < capacity && value[length] != '\0') ++length;
    return std::string(value, length);
}

void emitCpuid(std::ostream& out, const CpuidResult& v) {
    out << "{\"eax\":" << v.eax << ",\"ebx\":" << v.ebx
        << ",\"ecx\":" << v.ecx << ",\"edx\":" << v.edx << '}';
}

DriverStatus queryDriver() {
    DriverStatus result;
    HANDLE device = CreateFileW(
        L"\\\\.\\Ophion", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) { result.error = GetLastError(); return result; }

    DWORD returned = 0;
    HV_STATUS_V1 status{};
    BOOL ok = DeviceIoControl(device, IOCTL_HV_STATUS, nullptr, 0, &status,
        static_cast<DWORD>(sizeof(status)), &returned, nullptr);
    const DWORD firstError = ok ? ERROR_SUCCESS : GetLastError();
    if (ok && returned == sizeof(std::uint32_t)) {
        std::memcpy(&result.legacyProcessors, &status, sizeof(result.legacyProcessors));
        result.format = DriverStatus::Format::Legacy;
    } else if (ok && returned >= status.HeaderSize && status.Version == 1 &&
               status.HeaderSize >= offsetof(HV_STATUS_V1, AggregateExitCounters) &&
               status.Size >= status.HeaderSize && status.Size <= static_cast<DWORD>(sizeof(status))) {
        result.v1 = status;
        result.format = DriverStatus::Format::V1;
    } else {
        std::uint32_t legacy = 0;
        returned = 0;
        ok = DeviceIoControl(device, IOCTL_HV_STATUS, nullptr, 0, &legacy,
            static_cast<DWORD>(sizeof(legacy)), &returned, nullptr);
        if (ok && returned == sizeof(legacy)) {
            result.legacyProcessors = legacy;
            result.format = DriverStatus::Format::Legacy;
        } else {
            result.error = ok ? ERROR_INVALID_DATA : GetLastError();
            if (result.error == ERROR_SUCCESS) result.error = firstError;
        }
    }
    CloseHandle(device);
    return result;
}

bool pinAndMeasure(WORD group, BYTE number, unsigned sampleCount, ProcessorResult& result) {
    result.group = group;
    result.number = number;
    GROUP_AFFINITY desired{}, previous{};
    desired.Group = group;
    desired.Mask = static_cast<KAFFINITY>(1) << number;
    if (!SetThreadGroupAffinity(GetCurrentThread(), &desired, &previous)) {
        result.pinError = GetLastError();
        return false;
    }

    const CpuidResult maxBasic = cpuid(0);
    const std::uint32_t maxPlusOne = maxBasic.eax == UINT32_MAX ? 0x04201337u : maxBasic.eax + 1u;
    result.leaf1 = cpuid(1);
    result.hypervisorBase = cpuid(0x40000000u);
    result.hypervisorInterface = cpuid(0x40000001u);
    if ((result.leaf1.ecx & 0x80000000u) != 0 &&
        result.hypervisorBase.eax >= 0x40000001u &&
        result.hypervisorBase.eax <= 0x400000ffu) {
        const std::uint32_t last =
            result.hypervisorBase.eax < 0x4000000au
                ? result.hypervisorBase.eax
                : 0x4000000au;
        result.hypervisorLeaves.push_back(
            {0x40000000u, result.hypervisorBase});
        result.hypervisorLeaves.push_back(
            {0x40000001u, result.hypervisorInterface});
        for (std::uint32_t leaf = 0x40000002u;
             leaf <= last; ++leaf) {
            result.hypervisorLeaves.push_back(
                {leaf, cpuid(leaf)});
        }
    }
    result.invalidFixed = cpuid(0x04201337u);
    result.invalidMaxPlusOne = cpuid(maxPlusOne);
    result.samples.reserve(sampleCount);
    for (unsigned i = 0; i < sampleCount; ++i) {
        LARGE_INTEGER before{}, after{};
        QueryPerformanceCounter(&before);
        const std::uint64_t tscBefore = __rdtsc();
        (void)cpuid(0);
        const std::uint64_t tscAfter = __rdtsc();
        QueryPerformanceCounter(&after);
        result.samples.push_back({tscAfter - tscBefore, after.QuadPart - before.QuadPart});
    }

    if (!SetThreadGroupAffinity(GetCurrentThread(), &previous, nullptr)) {
        result.pinError = GetLastError();
        return false;
    }
    return true;
}

void emitStatus(std::ostream& out, const DriverStatus& status) {
    out << "\"status\":{";
    if (status.format == DriverStatus::Format::Unavailable) {
        out << "\"format\":\"unavailable\",\"win32Error\":" << status.error;
    } else if (status.format == DriverStatus::Format::Legacy) {
        out << "\"format\":\"legacy\",\"totalProcessors\":" << status.legacyProcessors;
    } else {
        const HV_STATUS_V1& v = status.v1;
        out << "\"format\":\"v1\",\"size\":" << v.Size << ",\"version\":" << v.Version
            << ",\"flags\":" << v.Flags << ",\"totalProcessors\":" << v.TotalProcessors
            << ",\"launchedProcessors\":" << v.LaunchedProcessors
            << ",\"detachedProcessors\":" << v.DetachedProcessors
            << ",\"failedProcessors\":" << v.FailedProcessors
            << ",\"terminalProcessors\":" << v.TerminalProcessors
            << ",\"parentFlags\":" << v.ParentFlags << ",\"parentFeatures\":" << v.ParentFeatures
            << ",\"capabilityFlags\":" << v.CapabilityFlags
            << ",\"preflightFailure\":" << v.PreflightFailure << ",\"lastFailure\":" << v.LastFailure
            << ",\"lastVmInstructionError\":" << v.LastVmInstructionError
            << ",\"physicalAddressBits\":" << v.PhysicalAddressBits
            << ",\"maximumGuestPhysicalAddress\":" << v.MaximumGuestPhysicalAddress
            << ",\"parentVendor\":" << jsonString(fixedString(v.ParentVendor, sizeof(v.ParentVendor)))
            << ",\"aggregateExitCounters\":[";
        for (std::size_t i = 0; i < sizeof(v.AggregateExitCounters) / sizeof(v.AggregateExitCounters[0]); ++i) {
            if (i) out << ',';
            out << v.AggregateExitCounters[i];
        }
        out << ']';
    }
    out << '}';
}

int emitError(const std::string& message) {
    std::cout << "{\"schema\":\"ophion.probe.v1\",\"error\":" << jsonString(message) << "}\n";
    return 2;
}

int emitHelp() {
    std::cout
        << "OphionProbe - all-core CPUID and timing probe\n"
        << "usage: OphionProbe.exe [--samples 1..100000]\n"
        << "       OphionProbe.exe --help\n";
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    unsigned sampleCount = kDefaultSamples;
    if (argc == 2 &&
        (std::string(argv[1]) == "--help" ||
         std::string(argv[1]) == "-h")) {
        return emitHelp();
    } else if (argc == 3 && std::string(argv[1]) == "--samples") {
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(argv[2], &end, 10);
        if (!end || *end != '\0' || parsed == 0 || parsed > 100000ul) return emitError("invalid --samples value");
        sampleCount = static_cast<unsigned>(parsed);
    } else if (argc != 1) return emitError("usage: OphionProbe.exe [--samples 1..100000]");

    LARGE_INTEGER frequency{};
    if (!QueryPerformanceFrequency(&frequency)) return emitError("QueryPerformanceFrequency failed");
    const DriverStatus status = queryDriver();
    std::vector<ProcessorResult> processors;
    bool allPinned = true;
    const WORD groupCount = GetActiveProcessorGroupCount();
    for (WORD group = 0; group < groupCount; ++group) {
        const DWORD count = GetActiveProcessorCount(group);
        if (count == 0 || count > sizeof(KAFFINITY) * 8) { allPinned = false; continue; }
        for (DWORD number = 0; number < count; ++number) {
            ProcessorResult processor{};
            if (!pinAndMeasure(group, static_cast<BYTE>(number), sampleCount, processor)) allPinned = false;
            processors.push_back(std::move(processor));
        }
    }

    std::cout << "{\"schema\":\"ophion.probe.v1\",\"sampleCount\":" << sampleCount
              << ",\"qpcFrequency\":" << frequency.QuadPart << ',';
    emitStatus(std::cout, status);
    std::cout << ",\"processors\":[";
    for (std::size_t i = 0; i < processors.size(); ++i) {
        if (i) std::cout << ',';
        const ProcessorResult& p = processors[i];
        std::cout << "{\"group\":" << p.group << ",\"number\":" << static_cast<unsigned>(p.number)
                  << ",\"pinError\":" << p.pinError << ",\"cpuid\":{";
        std::cout << "\"leaf1\":"; emitCpuid(std::cout, p.leaf1);
        std::cout << ",\"hypervisorBase\":"; emitCpuid(std::cout, p.hypervisorBase);
        std::cout << ",\"hypervisorInterface\":"; emitCpuid(std::cout, p.hypervisorInterface);
        std::cout << ",\"hypervisorLeaves\":[";
        for (std::size_t leaf = 0;
             leaf < p.hypervisorLeaves.size(); ++leaf) {
            if (leaf) std::cout << ',';
            std::cout << "{\"leaf\":"
                      << p.hypervisorLeaves[leaf].first << ',';
            std::cout << "\"eax\":"
                      << p.hypervisorLeaves[leaf].second.eax
                      << ",\"ebx\":"
                      << p.hypervisorLeaves[leaf].second.ebx
                      << ",\"ecx\":"
                      << p.hypervisorLeaves[leaf].second.ecx
                      << ",\"edx\":"
                      << p.hypervisorLeaves[leaf].second.edx << '}';
        }
        std::cout << ']';
        std::cout << ",\"invalidFixed\":"; emitCpuid(std::cout, p.invalidFixed);
        std::cout << ",\"invalidMaxPlusOne\":"; emitCpuid(std::cout, p.invalidMaxPlusOne);
        std::cout << "},\"timing\":[";
        for (std::size_t sample = 0; sample < p.samples.size(); ++sample) {
            if (sample) std::cout << ',';
            std::cout << "{\"tscDelta\":" << p.samples[sample].tscDelta
                      << ",\"qpcDelta\":" << p.samples[sample].qpcDelta << '}';
        }
        std::cout << "]}";
    }
    std::cout << "]}\n";
    return allPinned ? 0 : 1;
}
