#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace ophion::platform {

inline constexpr std::uint32_t kProtocolMagic = 0x4F50484EU; // OPHN
inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::uint16_t kMaxScatterRanges = 128;
inline constexpr std::uint32_t kMaxReadBytes = 1U << 20;
inline constexpr std::uint32_t kMaxRangeBytes = 64U << 10;

using Nonce = std::uint64_t;
using SnapshotEpoch = std::uint64_t;

enum class Command : std::uint16_t {
    DiscoverProcess = 1,
    ListModules = 2,
    TranslateVirtualAddress = 3,
    ScatterRead = 4,
    Status = 5,
    Snapshot = 6,
};

enum class Error : std::uint16_t {
    Ok = 0,
    BadVersion,
    BadCommand,
    MalformedRecord,
    LimitExceeded,
    CapabilityDenied,
    NonceMismatch,
    SessionClosed,
    InvalidAddress,
    AddressNotPresent,
    PhysicalRangeDenied,
    PartialRead,
    ProcessNotFound,
    ProcessExited,
    ProfileInvalid,
    FingerprintMismatch,
    TransportUnavailable,
    Unsupported,
};

enum class Capability : std::uint32_t {
    None = 0,
    Discovery = 1U << 0,
    Modules = 1U << 1,
    Translation = 1U << 2,
    Read = 1U << 3,
    Status = 1U << 4,
    Snapshot = 1U << 5,
};

constexpr Capability operator|(Capability left, Capability right) noexcept {
    return static_cast<Capability>(static_cast<std::uint32_t>(left) | static_cast<std::uint32_t>(right));
}
constexpr Capability operator&(Capability left, Capability right) noexcept {
    return static_cast<Capability>(static_cast<std::uint32_t>(left) & static_cast<std::uint32_t>(right));
}
constexpr bool has_capability(Capability granted, Capability requested) noexcept {
    return (granted & requested) == requested;
}
constexpr Capability capability_for(Command command) noexcept {
    switch (command) {
    case Command::DiscoverProcess: return Capability::Discovery;
    case Command::ListModules: return Capability::Modules;
    case Command::TranslateVirtualAddress: return Capability::Translation;
    case Command::ScatterRead: return Capability::Read;
    case Command::Status: return Capability::Status;
    case Command::Snapshot: return Capability::Snapshot;
    }
    return Capability::None;
}
constexpr bool is_read_only(Command command) noexcept { return capability_for(command) != Capability::None; }

#pragma pack(push, 1)
struct RecordHeader {
    std::uint32_t magic{kProtocolMagic};
    std::uint16_t version{kProtocolVersion};
    Command command{};
    std::uint32_t record_bytes{};
    Nonce nonce{};
    SnapshotEpoch snapshot_epoch{};
};

struct ResultHeader {
    RecordHeader request{};
    Error error{Error::Ok};
    std::uint16_t reserved{};
    std::uint32_t payload_bytes{};
};

struct ScatterDescriptor {
    std::uint64_t virtual_address{};
    std::uint32_t byte_count{};
    std::uint32_t destination_offset{};
};

struct ScatterReadRequest {
    RecordHeader header{};
    std::uint64_t directory_table_base{};
    std::uint32_t range_count{};
    std::uint32_t total_bytes{};
};

struct TranslateRequest {
    RecordHeader header{};
    std::uint64_t directory_table_base{};
    std::uint64_t virtual_address{};
};

struct DiscoveryRequest {
    RecordHeader header{};
    std::uint32_t pid{};
};

struct ModuleListRequest {
    RecordHeader header{};
    std::uint32_t pid{};
};

struct SessionState {
    Nonce nonce{};
    Capability capabilities{Capability::None};
    SnapshotEpoch epoch{};
    bool open{};
};
#pragma pack(pop)

static_assert(std::endian::native == std::endian::little, "Ophion protocol requires little-endian hosts");
static_assert(std::is_standard_layout_v<RecordHeader> && sizeof(RecordHeader) == 28);
static_assert(std::is_standard_layout_v<ResultHeader> && sizeof(ResultHeader) == 36);
static_assert(std::is_standard_layout_v<ScatterDescriptor> && sizeof(ScatterDescriptor) == 16);
static_assert(sizeof(ScatterReadRequest) == 44 && sizeof(TranslateRequest) == 44);
static_assert(sizeof(DiscoveryRequest) == 32 && sizeof(ModuleListRequest) == 32);

struct ScatterValidation {
    Error error{Error::Ok};
    std::uint32_t total_bytes{};
};

[[nodiscard]] Error validate_header(const RecordHeader& header, const SessionState& session) noexcept;
[[nodiscard]] ScatterValidation validate_scatter(std::span<const ScatterDescriptor> descriptors) noexcept;

} // namespace ophion::platform
