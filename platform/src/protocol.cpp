#include "ophion/platform/protocol.hpp"

#include <limits>

namespace ophion::platform {

Error validate_header(const RecordHeader& header, const SessionState& session) noexcept {
    if (header.magic != kProtocolMagic || header.version != kProtocolVersion) return Error::BadVersion;
    if (!is_read_only(header.command) || header.record_bytes < sizeof(RecordHeader)) return Error::BadCommand;
    if (!session.open) return Error::SessionClosed;
    if (header.nonce != session.nonce) return Error::NonceMismatch;
    if (!has_capability(session.capabilities, capability_for(header.command))) return Error::CapabilityDenied;
    return Error::Ok;
}

ScatterValidation validate_scatter(std::span<const ScatterDescriptor> descriptors) noexcept {
    if (descriptors.empty() || descriptors.size() > kMaxScatterRanges) return {Error::LimitExceeded, 0};

    std::uint64_t total = 0;
    for (const ScatterDescriptor& descriptor : descriptors) {
        if (descriptor.byte_count == 0 || descriptor.byte_count > kMaxRangeBytes ||
            descriptor.destination_offset > kMaxReadBytes - descriptor.byte_count) {
            return {Error::LimitExceeded, 0};
        }
        total += descriptor.byte_count;
        if (total > kMaxReadBytes || total > std::numeric_limits<std::uint32_t>::max()) {
            return {Error::LimitExceeded, 0};
        }
    }
    return {Error::Ok, static_cast<std::uint32_t>(total)};
}

} // namespace ophion::platform
