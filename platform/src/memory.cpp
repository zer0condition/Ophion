#include "ophion/platform/memory.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace ophion::platform {
namespace {
constexpr std::uint64_t kPageBytes = 0x1000;
constexpr std::uint64_t kPhysicalAddressMask = 0x000F'FFFF'FFFF'F000ULL;
constexpr std::uint64_t kPresent = 1;
constexpr std::uint64_t kLargePage = 1ULL << 7;

bool range_contains(std::uint64_t base, std::uint64_t bytes, std::uint64_t address, std::uint64_t count) noexcept {
    return address >= base && count <= bytes && address - base <= bytes - count;
}
} // namespace

bool PhysicalRange::contains(std::uint64_t address, std::uint64_t count) const noexcept {
    return range_contains(base, bytes, address, count);
}

void MockMemoryReader::map(std::uint64_t base, std::span<const std::byte> bytes) {
    regions_[base] = {bytes.begin(), bytes.end()};
}

ReadResult MockMemoryReader::read_physical(std::uint64_t address, std::span<std::byte> destination) const {
    if (destination.empty()) return {Error::Ok, 0};
    const auto candidate = regions_.upper_bound(address);
    if (candidate == regions_.begin()) return {Error::PhysicalRangeDenied, 0};
    const auto& [base, bytes] = *std::prev(candidate);
    if (address < base || address - base >= bytes.size()) return {Error::PhysicalRangeDenied, 0};

    const std::size_t offset = static_cast<std::size_t>(address - base);
    const std::size_t count = std::min(destination.size(), bytes.size() - offset);
    std::memcpy(destination.data(), bytes.data() + offset, count);
    return {count == destination.size() ? Error::Ok : Error::PartialRead, count};
}

PageTableWalker::PageTableWalker(const MemoryReader& memory, PageWalkOptions options)
    : memory_(memory), options_(std::move(options)) {
    if (options_.levels != 4 && options_.levels != 5) options_.levels = 0;
}

bool PageTableWalker::is_canonical(std::uint64_t virtual_address) const noexcept {
    if (options_.levels == 0) return false;
    const unsigned address_bits = options_.levels == 5 ? 57U : 48U;
    const std::uint64_t upper = virtual_address >> address_bits;
    const bool sign = (virtual_address & (1ULL << (address_bits - 1))) != 0;
    return upper == (sign ? (std::numeric_limits<std::uint64_t>::max() >> address_bits) : 0);
}

bool PageTableWalker::allowed(std::uint64_t address, std::uint64_t bytes) const noexcept {
    return std::any_of(options_.allowed_ranges.begin(), options_.allowed_ranges.end(),
                       [=](const PhysicalRange& range) { return range.contains(address, bytes); });
}

Error PageTableWalker::read_entry(std::uint64_t address, std::uint64_t& entry) const {
    std::array<std::byte, sizeof(entry)> raw{};
    const ReadResult read = read_physical(address, raw);
    if (read.bytes_read != raw.size()) return read.error == Error::Ok ? Error::PartialRead : read.error;
    std::memcpy(&entry, raw.data(), sizeof(entry));
    return Error::Ok;
}

Translation PageTableWalker::translate(std::uint64_t directory_table_base, std::uint64_t virtual_address) const {
    if (!is_canonical(virtual_address) || (directory_table_base & (kPageBytes - 1)) != 0) {
        return {Error::InvalidAddress, 0, 0};
    }

    std::uint64_t table = directory_table_base & kPhysicalAddressMask;
    if (!allowed(table, kPageBytes)) return {Error::PhysicalRangeDenied, 0, 0};

    for (int level = static_cast<int>(options_.levels) - 1; level >= 0; --level) {
        const std::uint64_t index = (virtual_address >> (12 + level * 9)) & 0x1FFULL;
        std::uint64_t entry = 0;
        const Error error = read_entry(table + index * sizeof(entry), entry);
        if (error != Error::Ok) return {error, 0, 0};
        if ((entry & kPresent) == 0) return {Error::AddressNotPresent, 0, 0};

        if ((level == 2 || level == 1) && (entry & kLargePage) != 0) {
            const std::uint64_t page_bytes = level == 2 ? (1ULL << 30) : (1ULL << 21);
            const std::uint64_t physical = (entry & ~(page_bytes - 1)) + (virtual_address & (page_bytes - 1));
            return allowed(physical, 1) ? Translation{Error::Ok, physical, page_bytes}
                                        : Translation{Error::PhysicalRangeDenied, 0, 0};
        }
        table = entry & kPhysicalAddressMask;
        if (level == 0) {
            const std::uint64_t physical = table + (virtual_address & (kPageBytes - 1));
            return allowed(physical, 1) ? Translation{Error::Ok, physical, kPageBytes}
                                        : Translation{Error::PhysicalRangeDenied, 0, 0};
        }
        if (!allowed(table, kPageBytes)) return {Error::PhysicalRangeDenied, 0, 0};
    }
    return {Error::AddressNotPresent, 0, 0};
}

ReadResult PageTableWalker::read_physical(std::uint64_t address, std::span<std::byte> destination) const {
    if (!allowed(address, destination.size())) return {Error::PhysicalRangeDenied, 0};
    return memory_.read_physical(address, destination);
}

ReadResult GuestMemoryReader::read(std::uint64_t virtual_address, std::span<std::byte> destination) const {
    std::size_t completed = 0;
    while (completed < destination.size()) {
        if (virtual_address > std::numeric_limits<std::uint64_t>::max() - completed) {
            return {Error::InvalidAddress, completed};
        }
        const Translation translated = walker_.translate(directory_table_base_, virtual_address + completed);
        if (translated.error != Error::Ok) return {translated.error, completed};
        const std::uint64_t page_offset = (virtual_address + completed) & (translated.page_bytes - 1);
        const std::size_t chunk = static_cast<std::size_t>(std::min<std::uint64_t>(
            destination.size() - completed, translated.page_bytes - page_offset));
        const ReadResult physical = walker_.read_physical(translated.physical_address, destination.subspan(completed, chunk));
        completed += physical.bytes_read;
        if (physical.bytes_read != chunk) {
            return {physical.error == Error::Ok ? Error::PartialRead : physical.error, completed};
        }
    }
    return {Error::Ok, completed};
}

ScatterPlan validate_and_coalesce(std::span<const ScatterPlanEntry> entries) noexcept {
    std::vector<ScatterDescriptor> descriptors;
    descriptors.reserve(entries.size());
    for (const ScatterPlanEntry& entry : entries) {
        if (entry.virtual_address > std::numeric_limits<std::uint64_t>::max() - entry.byte_count) return {Error::InvalidAddress, 0, {}};
        descriptors.push_back({entry.virtual_address, entry.byte_count, entry.destination_offset});
    }
    const ScatterValidation validation = validate_scatter(descriptors);
    if (validation.error != Error::Ok) return {validation.error, 0, {}};

    std::vector<ScatterPlanEntry> ordered(entries.begin(), entries.end());
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        return left.virtual_address < right.virtual_address;
    });
    for (std::size_t i = 1; i < ordered.size(); ++i) {
        const auto& previous = ordered[i - 1];
        const auto& current = ordered[i];
        if (current.virtual_address < previous.virtual_address + previous.byte_count) return {Error::MalformedRecord, 0, {}};
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        return left.destination_offset < right.destination_offset;
    });
    for (std::size_t i = 1; i < ordered.size(); ++i) {
        const auto& previous = ordered[i - 1];
        const auto& current = ordered[i];
        if (current.destination_offset < previous.destination_offset + previous.byte_count) return {Error::MalformedRecord, 0, {}};
    }
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        return left.virtual_address < right.virtual_address;
    });

    ScatterPlan plan{Error::Ok, validation.total_bytes, {}};
    for (const ScatterPlanEntry& entry : ordered) {
        if (!plan.reads.empty()) {
            CoalescedRead& last = plan.reads.back();
            if (last.virtual_address + last.byte_count == entry.virtual_address &&
                last.first_destination_offset + last.byte_count == entry.destination_offset &&
                last.byte_count <= kMaxRangeBytes - entry.byte_count) {
                last.byte_count += entry.byte_count;
                continue;
            }
        }
        plan.reads.push_back({entry.virtual_address, entry.byte_count, entry.destination_offset});
    }
    return plan;
}

ScatterReadResult scatter_read(const PageTableWalker& walker, std::uint64_t directory_table_base,
                               std::span<const ScatterPlanEntry> entries, std::span<std::byte> destination) {
    const ScatterPlan plan = validate_and_coalesce(entries);
    if (plan.error != Error::Ok) return {plan.error, 0, 0, 0};

    ScatterReadResult result{Error::Ok, plan.total_bytes, 0, 0};
    for (const CoalescedRead& read : plan.reads) {
        if (read.first_destination_offset > destination.size() ||
            read.byte_count > destination.size() - read.first_destination_offset) {
            return {Error::LimitExceeded, plan.total_bytes, result.completed_bytes, result.failed_ranges};
        }

        std::uint64_t virtual_address = read.virtual_address;
        std::uint32_t remaining = read.byte_count;
        std::uint32_t offset = read.first_destination_offset;
        while (remaining != 0) {
            const Translation translation = walker.translate(directory_table_base, virtual_address);
            if (translation.error != Error::Ok) {
                result.error = translation.error;
                ++result.failed_ranges;
                break;
            }
            const std::uint32_t page_remaining = static_cast<std::uint32_t>(
                translation.page_bytes - (virtual_address & (translation.page_bytes - 1)));
            const std::uint32_t chunk = std::min(remaining, page_remaining);
            const ReadResult physical = walker.read_physical(translation.physical_address,
                                                               destination.subspan(offset, chunk));
            result.completed_bytes += static_cast<std::uint32_t>(physical.bytes_read);
            virtual_address += physical.bytes_read;
            offset += static_cast<std::uint32_t>(physical.bytes_read);
            remaining -= static_cast<std::uint32_t>(physical.bytes_read);
            if (physical.bytes_read != chunk) {
                result.error = physical.error == Error::Ok ? Error::PartialRead : physical.error;
                ++result.failed_ranges;
                break;
            }
        }
    }
    if (result.completed_bytes != result.requested_bytes && result.error == Error::Ok) result.error = Error::PartialRead;
    return result;
}

} // namespace ophion::platform
