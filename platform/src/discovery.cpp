#include "ophion/platform/discovery.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace ophion::platform {
namespace {
constexpr std::uint32_t kMaximumProfileOffset = 0x4000;

bool valid_offset(std::uint32_t offset) noexcept { return offset != 0 && offset < kMaximumProfileOffset; }

template <typename T>
Error read_physical(const MemoryReader& memory, std::uint64_t address, T& value) {
    const ReadResult result = memory.read_physical(address, std::as_writable_bytes(std::span{&value, 1}));
    return result.bytes_read == sizeof(T) ? Error::Ok : (result.error == Error::Ok ? Error::PartialRead : result.error);
}

Error read_physical_bytes(const MemoryReader& memory, std::uint64_t address, std::span<std::byte> output) {
    const ReadResult result = memory.read_physical(address, output);
    return result.bytes_read == output.size() ? Error::Ok : (result.error == Error::Ok ? Error::PartialRead : result.error);
}

Error read_virtual(const PageTableWalker& memory, std::uint64_t cr3, std::uint64_t address, std::span<std::byte> output) {
    while (!output.empty()) {
        const Translation translation = memory.translate(cr3, address);
        if (translation.error != Error::Ok) return translation.error;
        const std::size_t in_page = static_cast<std::size_t>(translation.page_bytes - (address & (translation.page_bytes - 1)));
        const std::size_t chunk = std::min(output.size(), in_page);
        const ReadResult result = memory.read_physical(translation.physical_address, output.first(chunk));
        if (result.bytes_read != chunk) return result.error == Error::Ok ? Error::PartialRead : result.error;
        address += chunk;
        output = output.subspan(chunk);
    }
    return Error::Ok;
}

template <typename T>
Error read_virtual(const PageTableWalker& memory, std::uint64_t cr3, std::uint64_t address, T& value) {
    return read_virtual(memory, cr3, address, std::as_writable_bytes(std::span{&value, 1}));
}

struct ListEntry { std::uint64_t flink{}; std::uint64_t blink{}; };
struct UnicodeString { std::uint16_t length{}; std::uint16_t maximum_length{}; std::uint32_t padding{}; std::uint64_t buffer{}; };

std::string trim_image_name(std::array<char, 16> name) {
    const auto nul = std::find(name.begin(), name.end(), '\0');
    return {name.begin(), nul};
}
} // namespace

bool WindowsBuildProfile::valid() const noexcept {
    const auto& e = eprocess;
    const auto& l = ldr;
    return build_number != 0 && valid_offset(e.active_process_links) && valid_offset(e.unique_process_id) &&
           valid_offset(e.directory_table_base) && valid_offset(e.image_file_name) && valid_offset(e.peb) &&
           valid_offset(e.exit_time) && valid_offset(l.peb_ldr) && valid_offset(l.in_load_order_module_list) &&
           valid_offset(l.in_load_order_links) && valid_offset(l.dll_base) && valid_offset(l.size_of_image) &&
           valid_offset(l.time_date_stamp) && valid_offset(l.base_dll_name);
}

ProcessScan ProcessTracker::reconcile(std::vector<ProcessIdentity> observed) {
    std::unordered_map<std::uint32_t, bool> seen;
    for (ProcessIdentity& process : observed) {
        if (process.pid == 0 || process.directory_table_base == 0) continue;
        seen[process.pid] = true;
        auto [it, inserted] = processes_.try_emplace(process.pid);
        Current& current = it->second;
        if (inserted) current.generation = 1;
        else if (current.cr3 != process.directory_table_base || current.identity.exited) ++current.generation;
        current.cr3 = process.directory_table_base;
        process.generation = current.generation;
        process.exited = false;
        current.identity = process;
    }

    for (auto& [pid, current] : processes_) {
        if (!seen.contains(pid)) current.identity.exited = true;
    }

    ProcessScan result;
    result.processes.reserve(processes_.size());
    for (const auto& [_, current] : processes_) result.processes.push_back(current.identity);
    std::sort(result.processes.begin(), result.processes.end(), [](const auto& left, const auto& right) { return left.pid < right.pid; });
    return result;
}

std::optional<ProcessIdentity> ProcessTracker::find(std::uint32_t pid) const {
    const auto it = processes_.find(pid);
    return it == processes_.end() ? std::nullopt : std::optional<ProcessIdentity>{it->second.identity};
}

EprocessWalker::EprocessWalker(const MemoryReader& memory, const WindowsBuildProfile& profile, std::uint64_t system_process)
    : memory_(memory), profile_(profile), system_process_(system_process) {}

ProcessScan EprocessWalker::scan(ProcessTracker& tracker, std::size_t max_processes) const {
    if (!profile_.valid() || system_process_ == 0 || max_processes == 0 || max_processes > 4096) return {Error::ProfileInvalid, {}};

    std::vector<ProcessIdentity> observed;
    std::uint64_t current = system_process_;
    for (std::size_t count = 0; count < max_processes; ++count) {
        std::uint64_t pid = 0, cr3 = 0, peb = 0, exit_time = 0;
        std::array<char, 16> image{};
        if (read_physical(memory_, current + profile_.eprocess.unique_process_id, pid) != Error::Ok ||
            read_physical(memory_, current + profile_.eprocess.directory_table_base, cr3) != Error::Ok ||
            read_physical(memory_, current + profile_.eprocess.peb, peb) != Error::Ok ||
            read_physical(memory_, current + profile_.eprocess.exit_time, exit_time) != Error::Ok ||
            read_physical_bytes(memory_, current + profile_.eprocess.image_file_name,
                                std::as_writable_bytes(std::span{image})) != Error::Ok) {
            return {Error::PartialRead, {}};
        }
        if (pid <= std::numeric_limits<std::uint32_t>::max() && cr3 != 0 && exit_time == 0) {
            observed.push_back({static_cast<std::uint32_t>(pid), cr3 & ~0xFFFULL, peb, 0, trim_image_name(image), false});
        }

        ListEntry links{};
        const Error link_error = read_physical(memory_, current + profile_.eprocess.active_process_links, links);
        if (link_error != Error::Ok || links.flink < profile_.eprocess.active_process_links) return {Error::PartialRead, {}};
        const std::uint64_t next = links.flink - profile_.eprocess.active_process_links;
        if (next == system_process_) return tracker.reconcile(std::move(observed));
        current = next;
    }
    return {Error::LimitExceeded, {}};
}

std::array<std::byte, 32> Fnv1aDigest::hash(std::span<const std::byte> image) const {
    constexpr std::array<std::uint64_t, 4> seeds{0xcbf29ce484222325ULL, 0x9e3779b185ebca87ULL,
                                                   0x84222325cbf29ce4ULL, 0xd6e8feb86659fd93ULL};
    std::array<std::byte, 32> output{};
    for (std::size_t lane = 0; lane < seeds.size(); ++lane) {
        std::uint64_t state = seeds[lane];
        for (std::byte value : image) { state ^= std::to_integer<std::uint8_t>(value); state *= 0x100000001b3ULL; }
        std::memcpy(output.data() + lane * sizeof(state), &state, sizeof(state));
    }
    return output;
}

ImageFingerprint fingerprint(std::uint32_t timestamp, std::span<const std::byte> image, const ImageDigest& digest) {
    return {timestamp, static_cast<std::uint32_t>(image.size()), digest.hash(image)};
}

LdrWalker::LdrWalker(const PageTableWalker& memory, const WindowsBuildProfile& profile, const ImageDigest& digest)
    : memory_(memory), profile_(profile), digest_(digest) {}

std::pair<Error, std::vector<ModuleIdentity>> LdrWalker::modules(const ProcessIdentity& process, std::size_t max_modules) const {
    if (!profile_.valid() || process.exited || process.directory_table_base == 0 || process.peb == 0 ||
        max_modules == 0 || max_modules > 1024) return {Error::ProfileInvalid, {}};

    std::uint64_t ldr = 0;
    Error error = read_virtual(memory_, process.directory_table_base, process.peb + profile_.ldr.peb_ldr, ldr);
    if (error != Error::Ok || ldr == 0) return {error == Error::Ok ? Error::ProcessNotFound : error, {}};

    const std::uint64_t head = ldr + profile_.ldr.in_load_order_module_list;
    ListEntry list{};
    error = read_virtual(memory_, process.directory_table_base, head, list);
    if (error != Error::Ok) return {error, {}};

    std::vector<ModuleIdentity> modules;
    for (std::uint64_t link = list.flink; link != head; ) {
        if (modules.size() == max_modules || link < profile_.ldr.in_load_order_links) return {Error::LimitExceeded, {}};
        const std::uint64_t entry = link - profile_.ldr.in_load_order_links;
        std::uint64_t base = 0;
        std::uint32_t size = 0, timestamp = 0;
        UnicodeString name{};
        if ((error = read_virtual(memory_, process.directory_table_base, entry + profile_.ldr.dll_base, base)) != Error::Ok ||
            (error = read_virtual(memory_, process.directory_table_base, entry + profile_.ldr.size_of_image, size)) != Error::Ok ||
            (error = read_virtual(memory_, process.directory_table_base, entry + profile_.ldr.time_date_stamp, timestamp)) != Error::Ok ||
            (error = read_virtual(memory_, process.directory_table_base, entry + profile_.ldr.base_dll_name, name)) != Error::Ok) {
            return {error, {}};
        }
        if (size == 0 || size > kMaxReadBytes || name.length > 512 || (name.length & 1U) != 0) {
            return {Error::LimitExceeded, {}};
        }

        std::vector<std::byte> image(size);
        if ((error = read_virtual(memory_, process.directory_table_base, base, image)) != Error::Ok) return {error, {}};
        std::vector<char16_t> wide(name.length / sizeof(char16_t));
        if (!wide.empty() && (error = read_virtual(memory_, process.directory_table_base, name.buffer,
                                                    std::as_writable_bytes(std::span{wide}))) != Error::Ok) {
            return {error, {}};
        }
        std::string text;
        text.reserve(wide.size());
        for (char16_t ch : wide) text.push_back(ch <= 0x7F ? static_cast<char>(ch) : '?');
        modules.push_back({base, size, timestamp, std::move(text), fingerprint(timestamp, image, digest_)});

        if ((error = read_virtual(memory_, process.directory_table_base, link, list)) != Error::Ok) return {error, {}};
        link = list.flink;
    }
    return {Error::Ok, std::move(modules)};
}
} // namespace ophion::platform
