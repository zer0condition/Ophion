#pragma once

#include "ophion/platform/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

namespace ophion::platform {

struct PhysicalRange {
    std::uint64_t base{};
    std::uint64_t bytes{};
    [[nodiscard]] bool contains(std::uint64_t address, std::uint64_t count) const noexcept;
};

struct ReadResult {
    Error error{Error::Ok};
    std::size_t bytes_read{};
};

class MemoryReader {
public:
    virtual ~MemoryReader() = default;
    [[nodiscard]] virtual ReadResult read_physical(std::uint64_t address, std::span<std::byte> destination) const = 0;
};

class MockMemoryReader final : public MemoryReader {
public:
    void map(std::uint64_t base, std::span<const std::byte> bytes);
    [[nodiscard]] ReadResult read_physical(std::uint64_t address, std::span<std::byte> destination) const override;

private:
    std::map<std::uint64_t, std::vector<std::byte>> regions_;
};

struct PageWalkOptions {
    std::uint8_t levels{4};
    std::vector<PhysicalRange> allowed_ranges;
};

struct Translation {
    Error error{Error::Ok};
    std::uint64_t physical_address{};
    std::uint64_t page_bytes{};
};

class PageTableWalker {
public:
    PageTableWalker(const MemoryReader& memory, PageWalkOptions options);

    [[nodiscard]] bool is_canonical(std::uint64_t virtual_address) const noexcept;
    [[nodiscard]] Translation translate(std::uint64_t directory_table_base, std::uint64_t virtual_address) const;
    [[nodiscard]] ReadResult read_physical(std::uint64_t address, std::span<std::byte> destination) const;

private:
    [[nodiscard]] bool allowed(std::uint64_t address, std::uint64_t bytes) const noexcept;
    [[nodiscard]] Error read_entry(std::uint64_t address, std::uint64_t& entry) const;

    const MemoryReader& memory_;
    PageWalkOptions options_;
};

class GuestMemoryReader {
public:
    GuestMemoryReader(const PageTableWalker& walker, std::uint64_t directory_table_base) noexcept
        : walker_(walker), directory_table_base_(directory_table_base) {}

    [[nodiscard]] ReadResult read(std::uint64_t virtual_address, std::span<std::byte> destination) const;

    template <typename T>
    [[nodiscard]] ReadResult read_object(std::uint64_t virtual_address, T& output) const {
        return read(virtual_address, std::as_writable_bytes(std::span<T>(&output, 1)));
    }

private:
    const PageTableWalker& walker_;
    std::uint64_t directory_table_base_{};
};

struct ScatterPlanEntry {
    std::uint64_t virtual_address{};
    std::uint32_t byte_count{};
    std::uint32_t destination_offset{};
};

struct CoalescedRead {
    std::uint64_t virtual_address{};
    std::uint32_t byte_count{};
    std::uint32_t first_destination_offset{};
};

struct ScatterPlan {
    Error error{Error::Ok};
    std::uint32_t total_bytes{};
    std::vector<CoalescedRead> reads;
};

[[nodiscard]] ScatterPlan validate_and_coalesce(std::span<const ScatterPlanEntry> entries) noexcept;

struct ScatterReadResult {
    Error error{Error::Ok};
    std::uint32_t requested_bytes{};
    std::uint32_t completed_bytes{};
    std::uint32_t failed_ranges{};
};

[[nodiscard]] ScatterReadResult scatter_read(const PageTableWalker& walker, std::uint64_t directory_table_base,
                                               std::span<const ScatterPlanEntry> entries,
                                               std::span<std::byte> destination);

} // namespace ophion::platform
