#include "ophion/platform/internal.hpp"

#include <cstring>
#include <utility>

namespace ophion::platform {
namespace {
#pragma pack(push, 1)
struct DosHeader { std::uint16_t magic; std::uint8_t reserved[58]; std::uint32_t nt_offset; };
struct FileHeader { std::uint16_t machine; std::uint16_t section_count; std::uint32_t timestamp; std::uint32_t symbol_table; std::uint32_t symbol_count; std::uint16_t optional_bytes; std::uint16_t characteristics; };
struct OptionalHeader64 { std::uint16_t magic; std::uint8_t reserved0[14]; std::uint32_t entry_rva; std::uint32_t reserved1; std::uint64_t image_base; std::uint32_t section_alignment; std::uint32_t file_alignment; std::uint8_t reserved2[24]; std::uint32_t image_bytes; };
struct SectionHeader { std::uint8_t name[8]; std::uint32_t virtual_bytes; std::uint32_t rva; std::uint32_t raw_bytes; std::uint32_t raw_offset; std::uint8_t reserved[12]; std::uint32_t characteristics; };
#pragma pack(pop)
constexpr std::uint16_t kDosMagic = 0x5A4DU;
constexpr std::uint32_t kNtMagic = 0x00004550U;
constexpr std::uint16_t kPe32Plus = 0x20BU;

template <typename T>
bool read_at(std::span<const std::byte> image, std::size_t offset, T& value) noexcept {
    if (offset > image.size() || image.size() - offset < sizeof(T)) return false;
    std::memcpy(&value, image.data() + offset, sizeof(T));
    return true;
}

bool range_valid(std::size_t start, std::size_t count, std::size_t limit) noexcept {
    return start <= limit && count <= limit - start;
}
} // namespace

Error PeImagePlanner::build(std::span<const std::byte> image, ImageExecutionPlan& output) noexcept {
    output = {};
    DosHeader dos{};
    if (!read_at(image, 0, dos) || dos.magic != kDosMagic) return Error::MalformedRecord;
    const auto nt = static_cast<std::size_t>(dos.nt_offset);
    std::uint32_t signature{};
    FileHeader file{};
    OptionalHeader64 optional{};
    if (!read_at(image, nt, signature) || signature != kNtMagic ||
        !read_at(image, nt + sizeof(signature), file) ||
        file.section_count == 0 || file.section_count > 96 ||
        file.optional_bytes < sizeof(OptionalHeader64) ||
        !read_at(image, nt + sizeof(signature) + sizeof(file), optional) ||
        optional.magic != kPe32Plus || optional.image_bytes == 0 || optional.entry_rva >= optional.image_bytes) {
        return Error::MalformedRecord;
    }
    const std::size_t section_offset = nt + sizeof(signature) + sizeof(file) + file.optional_bytes;
    if (!range_valid(section_offset, static_cast<std::size_t>(file.section_count) * sizeof(SectionHeader), image.size())) {
        return Error::MalformedRecord;
    }

    ImageExecutionPlan plan{optional.image_base, optional.image_bytes, optional.entry_rva, {}};
    plan.sections.reserve(file.section_count);
    for (std::uint16_t i = 0; i < file.section_count; ++i) {
        SectionHeader section{};
        if (!read_at(image, section_offset + static_cast<std::size_t>(i) * sizeof(section), section) ||
            section.rva >= optional.image_bytes || section.virtual_bytes > optional.image_bytes - section.rva ||
            !range_valid(section.raw_offset, section.raw_bytes, image.size())) return Error::MalformedRecord;
        plan.sections.push_back({section.rva, section.virtual_bytes, section.raw_offset, section.raw_bytes, section.characteristics});
    }
    output = std::move(plan);
    return Error::Ok;
}

} // namespace ophion::platform
