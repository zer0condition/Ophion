#pragma once

#include "ophion/platform/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ophion::platform {

struct ImageSectionPlan {
    std::uint32_t rva{};
    std::uint32_t virtual_bytes{};
    std::uint32_t raw_offset{};
    std::uint32_t raw_bytes{};
    std::uint32_t characteristics{};
};

struct ImageExecutionPlan {
    std::uint64_t preferred_base{};
    std::uint32_t image_bytes{};
    std::uint32_t entry_rva{};
    std::vector<ImageSectionPlan> sections;
};

// Parses PE image layout into an immutable plan. It does not allocate remote
// memory, resolve imports, invoke TLS, change protection, or execute code.
class PeImagePlanner {
public:
    [[nodiscard]] static Error build(std::span<const std::byte> image, ImageExecutionPlan& output) noexcept;
};

} // namespace ophion::platform
