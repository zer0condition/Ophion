#include "ophion/platform/adapters.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace ophion::platform {

OffsetProfile::OffsetProfile(ImageFingerprint expected_image, std::vector<OffsetField> fields)
    : expected_image_(expected_image), fields_(std::move(fields)) {}

Error OffsetProfile::validate_shape() const noexcept {
    if (fields_.empty() || fields_.size() > 256) return Error::ProfileInvalid;
    for (std::size_t index = 0; index < fields_.size(); ++index) {
        if (fields_[index].name.empty() || fields_[index].offset >= kMaxReadBytes) return Error::ProfileInvalid;
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (fields_[previous].name == fields_[index].name) return Error::ProfileInvalid;
        }
    }
    return Error::Ok;
}

std::optional<ValidatedOffsetProfile> OffsetProfile::validate(const ImageFingerprint& actual) const {
    if (validate_shape() != Error::Ok || actual != expected_image_) return std::nullopt;
    return ValidatedOffsetProfile{*this};
}

std::optional<std::uint32_t> OffsetProfile::field(std::string_view name) const noexcept {
    const auto match = std::find_if(fields_.begin(), fields_.end(), [name](const OffsetField& field) { return field.name == name; });
    return match == fields_.end() ? std::nullopt : std::optional<std::uint32_t>{match->offset};
}

namespace {
constexpr std::uint32_t kMaxSnapshotEntities = 4096;

struct AdapterLayout {
    std::string_view array_rva;
    std::string_view count_rva;
    std::string_view root_offset;
    std::string_view translation_offset;
    std::string_view rotation_offset;
    std::string_view scale_offset;
};

bool add_offset(std::uint64_t base, std::uint32_t offset, std::uint64_t& result) noexcept {
    if (base > std::numeric_limits<std::uint64_t>::max() - offset) return false;
    result = base + offset;
    return true;
}

template <typename T>
Error read_exact(const GuestMemoryReader& reader, std::uint64_t address, T& output) {
    const ReadResult result = reader.read_object(address, output);
    return result.bytes_read == sizeof(T) ? Error::Ok : (result.error == Error::Ok ? Error::PartialRead : result.error);
}

Error required(const OffsetProfile& profile, std::string_view name, std::uint32_t& offset) {
    const auto value = profile.field(name);
    if (!value) return Error::ProfileInvalid;
    offset = *value;
    return Error::Ok;
}

Error materialize_snapshot(const GuestMemoryReader& reader, std::uint64_t module_base,
                           const ValidatedOffsetProfile& validated, const AdapterLayout& layout,
                           GameSnapshot& output) {
    output = {};
    const OffsetProfile& profile = validated.get();
    std::array<std::uint32_t, 6> fields{};
    const std::array<std::string_view, 6> names{layout.array_rva, layout.count_rva, layout.root_offset,
                                                 layout.translation_offset, layout.rotation_offset, layout.scale_offset};
    for (std::size_t i = 0; i < names.size(); ++i) {
        const Error error = required(profile, names[i], fields[i]);
        if (error != Error::Ok) return error;
    }
    const std::uint32_t pointer_stride = profile.field("entity_pointer_stride").value_or(sizeof(std::uint64_t));
    if (pointer_stride < sizeof(std::uint64_t) || pointer_stride > 4096) return Error::ProfileInvalid;

    std::uint64_t array_address{};
    std::uint64_t count_address{};
    if (!add_offset(module_base, fields[0], array_address) || !add_offset(module_base, fields[1], count_address)) {
        return Error::InvalidAddress;
    }
    std::uint64_t entities{};
    std::uint32_t count{};
    if (const Error error = read_exact(reader, array_address, entities); error != Error::Ok) return error;
    if (const Error error = read_exact(reader, count_address, count); error != Error::Ok) return error;
    if (count > kMaxSnapshotEntities || (count != 0 && entities == 0)) return Error::LimitExceeded;

    output.entities.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint64_t indexed = static_cast<std::uint64_t>(i) * pointer_stride;
        if (entities > std::numeric_limits<std::uint64_t>::max() - indexed) return Error::InvalidAddress;
        std::uint64_t entity{};
        if (const Error error = read_exact(reader, entities + indexed, entity); error != Error::Ok) return error;
        if (entity == 0) continue;

        std::uint64_t root_address{};
        if (!add_offset(entity, fields[2], root_address)) return Error::InvalidAddress;
        std::uint64_t root{};
        if (const Error error = read_exact(reader, root_address, root); error != Error::Ok) return error;
        if (root == 0) continue;

        Transform transform{};
        std::uint64_t component_address{};
        if (!add_offset(root, fields[3], component_address)) return Error::InvalidAddress;
        if (const Error error = read_exact(reader, component_address, transform.translation); error != Error::Ok) return error;
        if (!add_offset(root, fields[4], component_address)) return Error::InvalidAddress;
        if (const Error error = read_exact(reader, component_address, transform.rotation); error != Error::Ok) return error;
        if (!add_offset(root, fields[5], component_address)) return Error::InvalidAddress;
        if (const Error error = read_exact(reader, component_address, transform.scale); error != Error::Ok) return error;
        output.entities.push_back({entity, transform, {}});
    }
    output.epoch = 1;
    return Error::Ok;
}
} // namespace

Error UnrealAdapter::snapshot(GameSnapshot& output) const {
    return materialize_snapshot(reader_, module_base_, profile_,
                                {"actor_array_rva", "actor_count_rva", "actor_root_offset",
                                 "root_translation_offset", "root_rotation_offset", "root_scale_offset"}, output);
}

Error UnityIl2CppAdapter::snapshot(GameSnapshot& output) const {
    return materialize_snapshot(reader_, module_base_, profile_,
                                {"object_array_rva", "object_count_rva", "object_root_offset",
                                 "transform_translation_offset", "transform_rotation_offset", "transform_scale_offset"}, output);
}

Error Source2Adapter::snapshot(GameSnapshot& output) const {
    return materialize_snapshot(reader_, module_base_, profile_,
                                {"entity_list_rva", "entity_count_rva", "entity_root_offset",
                                 "scene_translation_offset", "scene_rotation_offset", "scene_scale_offset"}, output);
}

} // namespace ophion::platform
