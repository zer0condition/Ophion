#pragma once

#include "ophion/platform/memory.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace ophion::platform {

struct EprocessOffsets {
    std::uint32_t active_process_links{};
    std::uint32_t unique_process_id{};
    std::uint32_t directory_table_base{};
    std::uint32_t image_file_name{};
    std::uint32_t peb{};
    std::uint32_t exit_time{};
};

struct LdrOffsets {
    std::uint32_t peb_ldr{};
    std::uint32_t in_load_order_module_list{};
    std::uint32_t in_load_order_links{};
    std::uint32_t dll_base{};
    std::uint32_t size_of_image{};
    std::uint32_t time_date_stamp{};
    std::uint32_t base_dll_name{};
};

struct WindowsBuildProfile {
    std::uint32_t build_number{};
    EprocessOffsets eprocess{};
    LdrOffsets ldr{};
    [[nodiscard]] bool valid() const noexcept;
};

struct ProcessIdentity {
    std::uint32_t pid{};
    std::uint64_t directory_table_base{};
    std::uint64_t peb{};
    std::uint64_t generation{};
    std::string image_name;
    bool exited{};
};

struct ProcessScan {
    Error error{Error::Ok};
    std::vector<ProcessIdentity> processes;
};

class ProcessTracker {
public:
    [[nodiscard]] ProcessScan reconcile(std::vector<ProcessIdentity> observed);
    [[nodiscard]] std::optional<ProcessIdentity> find(std::uint32_t pid) const;

private:
    struct Current { std::uint64_t cr3{}; std::uint64_t generation{}; ProcessIdentity identity; };
    std::unordered_map<std::uint32_t, Current> processes_;
};

class EprocessWalker {
public:
    EprocessWalker(const MemoryReader& memory, const WindowsBuildProfile& profile, std::uint64_t system_process);
    [[nodiscard]] ProcessScan scan(ProcessTracker& tracker, std::size_t max_processes = 4096) const;

private:
    const MemoryReader& memory_;
    const WindowsBuildProfile& profile_;
    std::uint64_t system_process_{};
};

struct ImageFingerprint {
    std::uint32_t time_date_stamp{};
    std::uint32_t image_size{};
    std::array<std::byte, 32> digest{};
    constexpr bool operator==(const ImageFingerprint&) const noexcept = default;
};

class ImageDigest {
public:
    virtual ~ImageDigest() = default;
    [[nodiscard]] virtual std::array<std::byte, 32> hash(std::span<const std::byte> image) const = 0;
};

class Fnv1aDigest final : public ImageDigest {
public:
    [[nodiscard]] std::array<std::byte, 32> hash(std::span<const std::byte> image) const override;
};

[[nodiscard]] ImageFingerprint fingerprint(std::uint32_t timestamp, std::span<const std::byte> image,
                                           const ImageDigest& digest);

struct ModuleIdentity {
    std::uint64_t base{};
    std::uint32_t size{};
    std::uint32_t timestamp{};
    std::string name;
    ImageFingerprint fingerprint{};
};

class LdrWalker {
public:
    LdrWalker(const PageTableWalker& memory, const WindowsBuildProfile& profile, const ImageDigest& digest);
    [[nodiscard]] std::pair<Error, std::vector<ModuleIdentity>> modules(const ProcessIdentity& process,
                                                                          std::size_t max_modules = 1024) const;

private:
    const PageTableWalker& memory_;
    const WindowsBuildProfile& profile_;
    const ImageDigest& digest_;
};

} // namespace ophion::platform
