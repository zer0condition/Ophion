#include "ophion/platform/transport.hpp"

#include <iostream>

int main() {
    using namespace ophion::platform;

    MockMemoryReader memory;
    PageTableWalker walker(memory, {4, {}});
    MockTransport transport(walker);
    const SessionState session = transport.attach(0x12345678ULL, Capability::Status | Capability::Snapshot);
    if (!session.open) return 1;

    RecordHeader request{};
    request.command = Command::Snapshot;
    request.record_bytes = sizeof(request);
    request.nonce = session.nonce;
    const TransportResult result = transport.snapshot(request);
    if (result.error != Error::Ok) return 1;

    std::cout << "{\"transport\":\"mock\",\"epoch\":" << result.epoch << ",\"error\":\"Ok\"}\n";
    return 0;
}
