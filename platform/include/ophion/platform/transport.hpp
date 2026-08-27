#pragma once

#include "ophion/platform/discovery.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace ophion::platform {

struct TransportResult {
    Error error{Error::Ok};
    SnapshotEpoch epoch{};
    std::uint64_t value{};
    std::uint32_t completed_bytes{};
};

class InProcessRingTransport {
public:
    explicit InProcessRingTransport(const PageTableWalker& walker) noexcept : walker_(walker) {}

    [[nodiscard]] SessionState attach(Nonce client_nonce, Capability requested) noexcept;
    void close() noexcept;
    [[nodiscard]] TransportResult status(const RecordHeader& header) noexcept;
    void set_process_catalog(std::vector<ProcessIdentity> processes);
    void set_module_catalog(std::uint32_t pid, std::vector<ModuleIdentity> modules);
    [[nodiscard]] TransportResult discover(const DiscoveryRequest& request, ProcessIdentity& output) noexcept;
    [[nodiscard]] TransportResult list_modules(const ModuleListRequest& request, std::vector<ModuleIdentity>& output) noexcept;
    [[nodiscard]] TransportResult translate(const TranslateRequest& request) noexcept;
    [[nodiscard]] TransportResult scatter(const ScatterReadRequest& request, std::span<const ScatterDescriptor> descriptors,
                                          std::span<std::byte> output) noexcept;
    [[nodiscard]] TransportResult snapshot(const RecordHeader& header) noexcept;
    [[nodiscard]] std::size_t ring_depth() const noexcept { return count_; }

private:
    [[nodiscard]] Error accept(const RecordHeader& header, Command expected) noexcept;
    void record(Command command) noexcept;

    const PageTableWalker& walker_;
    SessionState session_{};
    std::array<Command, 64> commands_{};
    std::size_t head_{};
    std::size_t count_{};
    std::vector<ProcessIdentity> processes_;
    std::unordered_map<std::uint32_t, std::vector<ModuleIdentity>> modules_;
};

using MockTransport = InProcessRingTransport;

} // namespace ophion::platform
