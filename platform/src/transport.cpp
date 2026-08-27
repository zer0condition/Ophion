#include "ophion/platform/transport.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace ophion::platform {
namespace {
constexpr Capability kMockCapabilities = Capability::Discovery | Capability::Modules | Capability::Translation |
                                       Capability::Read | Capability::Status | Capability::Snapshot;
}

SessionState InProcessRingTransport::attach(Nonce client_nonce, Capability requested) noexcept {
    if (client_nonce == 0) return {};
    session_ = {client_nonce ^ 0x9E3779B97F4A7C15ULL,
                static_cast<Capability>(static_cast<std::uint32_t>(requested) & static_cast<std::uint32_t>(kMockCapabilities)),
                0, true};
    if (session_.capabilities == Capability::None) session_.open = false;
    return session_;
}

void InProcessRingTransport::close() noexcept { session_ = {}; }

void InProcessRingTransport::set_process_catalog(std::vector<ProcessIdentity> processes) {
    processes_ = std::move(processes);
}

void InProcessRingTransport::set_module_catalog(std::uint32_t pid, std::vector<ModuleIdentity> modules) {
    modules_[pid] = std::move(modules);
}

TransportResult InProcessRingTransport::discover(const DiscoveryRequest& request, ProcessIdentity& output) noexcept {
    output = {};
    if (request.header.record_bytes != sizeof(request)) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(request.header, Command::DiscoverProcess);
    if (error != Error::Ok) return {error, session_.epoch, 0, 0};
    const auto process = std::find_if(processes_.begin(), processes_.end(),
                                      [&request](const ProcessIdentity& candidate) { return candidate.pid == request.pid; });
    if (process == processes_.end()) return {Error::ProcessNotFound, session_.epoch, 0, 0};
    if (process->exited) return {Error::ProcessExited, session_.epoch, 0, 0};
    output = *process;
    return {Error::Ok, session_.epoch, output.generation, 0};
}

TransportResult InProcessRingTransport::list_modules(const ModuleListRequest& request,
                                                     std::vector<ModuleIdentity>& output) noexcept {
    output.clear();
    if (request.header.record_bytes != sizeof(request)) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(request.header, Command::ListModules);
    if (error != Error::Ok) return {error, session_.epoch, 0, 0};
    const auto process = std::find_if(processes_.begin(), processes_.end(),
                                      [&request](const ProcessIdentity& candidate) { return candidate.pid == request.pid; });
    if (process == processes_.end()) return {Error::ProcessNotFound, session_.epoch, 0, 0};
    if (process->exited) return {Error::ProcessExited, session_.epoch, 0, 0};
    const auto modules = modules_.find(request.pid);
    if (modules != modules_.end()) output = modules->second;
    return {Error::Ok, session_.epoch, static_cast<std::uint64_t>(output.size()), 0};
}

Error InProcessRingTransport::accept(const RecordHeader& header, Command expected) noexcept {
    if (header.command != expected) return Error::BadCommand;
    const Error error = validate_header(header, session_);
    if (error != Error::Ok) return error;
    if (header.snapshot_epoch > session_.epoch) return Error::MalformedRecord;
    record(expected);
    return Error::Ok;
}

void InProcessRingTransport::record(Command command) noexcept {
    commands_[head_] = command;
    head_ = (head_ + 1) % commands_.size();
    if (count_ < commands_.size()) ++count_;
}

TransportResult InProcessRingTransport::status(const RecordHeader& header) noexcept {
    if (header.record_bytes != sizeof(header)) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(header, Command::Status);
    return {error, session_.epoch, static_cast<std::uint64_t>(count_), 0};
}

TransportResult InProcessRingTransport::translate(const TranslateRequest& request) noexcept {
    if (request.header.record_bytes != sizeof(request)) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(request.header, Command::TranslateVirtualAddress);
    if (error != Error::Ok) return {error, session_.epoch, 0, 0};
    const Translation translated = walker_.translate(request.directory_table_base, request.virtual_address);
    return {translated.error, session_.epoch, translated.physical_address, 0};
}

TransportResult InProcessRingTransport::scatter(const ScatterReadRequest& request, std::span<const ScatterDescriptor> descriptors,
                                                std::span<std::byte> output) noexcept {
    const std::size_t expected_bytes = sizeof(request) + descriptors.size() * sizeof(ScatterDescriptor);
    if (request.header.record_bytes != expected_bytes) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(request.header, Command::ScatterRead);
    if (error != Error::Ok) return {error, session_.epoch, 0, 0};
    const ScatterValidation validation = validate_scatter(descriptors);
    if (request.range_count != descriptors.size() || validation.error != Error::Ok || request.total_bytes != validation.total_bytes) {
        return {Error::MalformedRecord, session_.epoch, 0, 0};
    }

    std::vector<ScatterPlanEntry> plan;
    plan.reserve(descriptors.size());
    for (const ScatterDescriptor& descriptor : descriptors) {
        plan.push_back({descriptor.virtual_address, descriptor.byte_count, descriptor.destination_offset});
    }
    const ScatterReadResult read = scatter_read(walker_, request.directory_table_base, plan, output);
    return {read.error, session_.epoch, 0, read.completed_bytes};
}

TransportResult InProcessRingTransport::snapshot(const RecordHeader& header) noexcept {
    if (header.record_bytes != sizeof(header)) return {Error::MalformedRecord, session_.epoch, 0, 0};
    const Error error = accept(header, Command::Snapshot);
    if (error != Error::Ok) return {error, session_.epoch, 0, 0};
    ++session_.epoch;
    return {Error::Ok, session_.epoch, 0, 0};
}

} // namespace ophion::platform
