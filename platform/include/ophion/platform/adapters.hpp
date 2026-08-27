#pragma once

#include "ophion/platform/discovery.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>
#include <utility>

namespace ophion::platform {

struct OffsetField {
    std::string_view name;
    std::uint32_t offset{};
};

class ValidatedOffsetProfile;

class OffsetProfile {
public:
    OffsetProfile(ImageFingerprint expected_image, std::vector<OffsetField> fields);
    [[nodiscard]] Error validate_shape() const noexcept;
    [[nodiscard]] std::optional<ValidatedOffsetProfile> validate(const ImageFingerprint& actual) const;
    [[nodiscard]] std::optional<std::uint32_t> field(std::string_view name) const noexcept;

private:
    ImageFingerprint expected_image_{};
    std::vector<OffsetField> fields_;
};

class ValidatedOffsetProfile {
public:
    ValidatedOffsetProfile(const ValidatedOffsetProfile&) = default;
    ValidatedOffsetProfile(ValidatedOffsetProfile&&) noexcept = default;
    ValidatedOffsetProfile& operator=(const ValidatedOffsetProfile&) = default;
    ValidatedOffsetProfile& operator=(ValidatedOffsetProfile&&) noexcept = default;
    [[nodiscard]] const OffsetProfile& get() const noexcept { return *profile_; }

private:
    friend class OffsetProfile;
    explicit ValidatedOffsetProfile(const OffsetProfile& profile) noexcept : profile_(&profile) {}
    const OffsetProfile* profile_;
};

struct Vec3 { float x{}; float y{}; float z{}; };
struct Quat { float x{}; float y{}; float z{}; float w{1.0F}; };
struct Transform { Vec3 translation{}; Quat rotation{}; Vec3 scale{1.0F, 1.0F, 1.0F}; };
struct CameraSnapshot { Transform transform{}; float vertical_fov{}; float aspect_ratio{}; };
struct BoneSnapshot { std::uint32_t index{}; Transform transform{}; };
struct EntitySnapshot { std::uint64_t identity{}; Transform transform{}; std::vector<BoneSnapshot> bones; };
struct ModuleSnapshot { std::uint64_t base{}; std::uint32_t size{}; ImageFingerprint fingerprint{}; };
struct GameSnapshot {
    SnapshotEpoch epoch{};
    CameraSnapshot camera{};
    std::vector<EntitySnapshot> entities;
    std::vector<ModuleSnapshot> modules;
};

class GameAdapter {
public:
    virtual ~GameAdapter() = default;
    [[nodiscard]] virtual Error snapshot(GameSnapshot& output) const = 0;
};

class UnrealAdapter final : public GameAdapter {
public:
    UnrealAdapter(const GuestMemoryReader& reader, std::uint64_t module_base, ValidatedOffsetProfile profile)
        : reader_(reader), module_base_(module_base), profile_(std::move(profile)) {}
    [[nodiscard]] Error snapshot(GameSnapshot& output) const override;
private:
    const GuestMemoryReader& reader_;
    std::uint64_t module_base_{};
    ValidatedOffsetProfile profile_;
};

class UnityIl2CppAdapter final : public GameAdapter {
public:
    UnityIl2CppAdapter(const GuestMemoryReader& reader, std::uint64_t module_base, ValidatedOffsetProfile profile)
        : reader_(reader), module_base_(module_base), profile_(std::move(profile)) {}
    [[nodiscard]] Error snapshot(GameSnapshot& output) const override;
private:
    const GuestMemoryReader& reader_;
    std::uint64_t module_base_{};
    ValidatedOffsetProfile profile_;
};

class Source2Adapter final : public GameAdapter {
public:
    Source2Adapter(const GuestMemoryReader& reader, std::uint64_t module_base, ValidatedOffsetProfile profile)
        : reader_(reader), module_base_(module_base), profile_(std::move(profile)) {}
    [[nodiscard]] Error snapshot(GameSnapshot& output) const override;
private:
    const GuestMemoryReader& reader_;
    std::uint64_t module_base_{};
    ValidatedOffsetProfile profile_;
};

} // namespace ophion::platform
