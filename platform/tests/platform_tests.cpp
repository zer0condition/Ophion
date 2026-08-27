#include "ophion/platform/adapters.hpp"
#include "ophion/platform/internal.hpp"
#include "ophion/platform/memory.hpp"
#include "ophion/platform/overlay.hpp"
#include "ophion/platform/protocol.hpp"
#include "ophion/platform/transport.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <vector>

using namespace ophion::platform;

namespace {
std::vector<std::byte> page(std::initializer_list<std::pair<std::size_t, std::uint64_t>> entries) {
    std::vector<std::byte> bytes(0x1000);
    for (const auto& [index, value] : entries) std::memcpy(bytes.data() + index * sizeof(value), &value, sizeof(value));
    return bytes;
}

void test_protocol_layout_and_bounds() {
    static_assert(sizeof(RecordHeader) == 28);
    const ScatterDescriptor ranges[]{{0x1000, 4, 0}, {0x1004, 4, 4}};
    assert(validate_scatter(ranges).error == Error::Ok);
    const ScatterDescriptor bad[]{{0x1000, 0, 0}};
    assert(validate_scatter(bad).error == Error::LimitExceeded);
}

void test_four_level_large_page() {
    MockMemoryReader memory;
    constexpr std::uint64_t va = 0x12345000ULL;
    memory.map(0x1000, page({{0, 0x2001}}));
    memory.map(0x2000, page({{0, 0x3001}}));
    memory.map(0x3000, page({{(va >> 21) & 0x1ff, 0x40000000ULL | 0x81}}));
    PageTableWalker walker(memory, {4, {{0x1000, 0x3000}, {0x40000000ULL, 0x200000}}});
    const Translation translated = walker.translate(0x1000, va);
    assert(translated.error == Error::Ok);
    assert(translated.physical_address == 0x40000000ULL + (va & 0x1fffffULL));
    assert(translated.page_bytes == 0x200000);
}

void test_five_level_walk() {
    MockMemoryReader memory;
    constexpr std::uint64_t va = 0x0001000000001000ULL;
    memory.map(0x1000, page({{1, 0x2001}}));
    memory.map(0x2000, page({{0, 0x3001}}));
    memory.map(0x3000, page({{0, 0x4001}}));
    memory.map(0x4000, page({{0, 0x5001}}));
    memory.map(0x5000, page({{1, 0x7001}}));
    PageTableWalker walker(memory, {5, {{0x1000, 0x7000}}});
    const Translation translated = walker.translate(0x1000, va);
    assert(translated.error == Error::Ok && translated.physical_address == 0x7000);
}

void test_scatter_coalescing() {
    const ScatterPlanEntry entries[]{{0x1000, 4, 0}, {0x1004, 4, 4}, {0x2000, 4, 8}};
    const ScatterPlan plan = validate_and_coalesce(entries);
    assert(plan.error == Error::Ok && plan.total_bytes == 12 && plan.reads.size() == 2);
    const ScatterPlanEntry overlap[]{{0x1000, 4, 0}, {0x1002, 4, 4}};
    assert(validate_and_coalesce(overlap).error == Error::MalformedRecord);
}

void test_process_lifecycle() {
    ProcessTracker tracker;
    [[maybe_unused]] const auto first = tracker.reconcile({{42, 0x1000, 0, 0, "mock.exe", false}});
    assert(tracker.find(42)->generation == 1);
    [[maybe_unused]] const auto changed = tracker.reconcile({{42, 0x2000, 0, 0, "mock.exe", false}});
    assert(tracker.find(42)->generation == 2);
    [[maybe_unused]] const auto exited = tracker.reconcile({});
    assert(tracker.find(42)->exited);
}

void test_fingerprint_gate() {
    ImageFingerprint expected{};
    expected.time_date_stamp = 1;
    expected.image_size = 4;
    expected.digest[0] = std::byte{1};
    OffsetProfile profile(expected, {{"world", 16}});
    ImageFingerprint actual = expected;
    actual.digest[0] = std::byte{2};
    assert(!profile.validate(actual).has_value());
    assert(profile.validate(expected).has_value());
}

void test_nonce_handshake() {
    MockMemoryReader memory;
    PageTableWalker walker(memory, {4, {}});
    MockTransport transport(walker);
    const SessionState session = transport.attach(7, Capability::Status | Capability::Snapshot);
    RecordHeader status{};
    status.command = Command::Status;
    status.record_bytes = sizeof(status);
    status.nonce = session.nonce + 1;
    assert(transport.status(status).error == Error::NonceMismatch);
    status.nonce = session.nonce;
    assert(transport.status(status).error == Error::Ok);
}
void test_discovery_and_module_transport() {
    MockMemoryReader memory;
    PageTableWalker walker(memory, {4, {}});
    MockTransport transport(walker);
    const SessionState session = transport.attach(8, Capability::Discovery | Capability::Modules);
    transport.set_process_catalog({{7, 0x1000, 0x2000, 3, "mock.exe", false}});
    transport.set_module_catalog(7, {{0x100000, 0x3000, 42, "mock.dll", {}}});

    DiscoveryRequest discovery{};
    discovery.header = {kProtocolMagic, kProtocolVersion, Command::DiscoverProcess, sizeof(discovery), session.nonce, 0};
    discovery.pid = 7;
    ProcessIdentity process{};
    assert(transport.discover(discovery, process).error == Error::Ok && process.generation == 3);
    ModuleListRequest list{};
    list.header = {kProtocolMagic, kProtocolVersion, Command::ListModules, sizeof(list), session.nonce, 0};
    list.pid = 7;
    std::vector<ModuleIdentity> modules;
    assert(transport.list_modules(list, modules).value == 1 && modules.front().name == "mock.dll");
}

void test_transport_scatter_read() {
    MockMemoryReader memory;
    constexpr std::uint64_t va = 0x12345000ULL;
    memory.map(0x1000, page({{0, 0x2001}}));
    memory.map(0x2000, page({{0, 0x3001}}));
    memory.map(0x3000, page({{(va >> 21) & 0x1ff, 0x40000000ULL | 0x81}}));
    std::vector<std::byte> backing(0x200000);
    const std::array<std::byte, 8> expected{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                            std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    std::memcpy(backing.data() + (va & 0x1fffffULL), expected.data(), expected.size());
    memory.map(0x40000000ULL, backing);
    PageTableWalker walker(memory, {4, {{0x1000, 0x3000}, {0x40000000ULL, 0x200000}}});
    MockTransport transport(walker);
    const SessionState session = transport.attach(9, Capability::Read);
    ScatterReadRequest request{};
    request.header = {kProtocolMagic, kProtocolVersion, Command::ScatterRead,
                      static_cast<std::uint32_t>(sizeof(request) + 2 * sizeof(ScatterDescriptor)), session.nonce, 0};
    request.directory_table_base = 0x1000;
    request.range_count = 2;
    request.total_bytes = 8;
    const std::array<ScatterDescriptor, 2> descriptors{{{va, 4, 0}, {va + 4, 4, 4}}};
    std::array<std::byte, 8> output{};
    const TransportResult result = transport.scatter(request, descriptors, output);
    assert(result.error == Error::Ok && result.completed_bytes == output.size() && output == expected);
}

class StubProjector final : public WorldProjector {
public:
    [[nodiscard]] bool project(const Vec3& world, ScreenPoint& screen) const override {
        if (world.z < 0.0F) return false;
        screen = {world.x, world.y};
        return true;
    }
};

void test_overlay_model_and_image_rejection() {
    GameSnapshot snapshot{};
    snapshot.entities.push_back({42, {{50.0F, 50.0F, 1.0F}, {}, {}}, {}});
    snapshot.entities.push_back({99, {{50.0F, 50.0F, -1.0F}, {}, {}}, {}});
    const StubProjector projector;
    const ExternalOverlayModel overlay;
    const auto commands = overlay.build(snapshot, projector, {100.0F, 100.0F});
    assert(commands.size() == 2 && commands[0].kind == DrawKind::Box && commands[1].text == "42");
    ImageExecutionPlan plan{};
    const std::array<std::byte, 64> invalid{};
    assert(PeImagePlanner::build(invalid, plan) == Error::MalformedRecord);
}

template <typename T>
void put(std::vector<std::byte>& bytes, std::size_t offset, const T& value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void test_guest_reader_and_unreal_adapter() {
    MockMemoryReader memory;
    memory.map(0x1000, page({{0, 0x2001}}));
    memory.map(0x2000, page({{0, 0x3001}}));
    memory.map(0x3000, page({{2, 0x4001}}));
    memory.map(0x4000, page({{0, 0x5001}}));
    std::vector<std::byte> data(0x1000);
    const std::uint64_t actor_array = 0x400200;
    const std::uint32_t actor_count = 1;
    const std::uint64_t actor = 0x400300;
    const std::uint64_t root = 0x400400;
    const Vec3 translation{1.0F, 2.0F, 3.0F};
    const Quat rotation{0.0F, 0.0F, 0.0F, 1.0F};
    const Vec3 scale{1.0F, 1.0F, 1.0F};
    put(data, 0x000, actor_array);
    put(data, 0x008, actor_count);
    put(data, 0x200, actor);
    put(data, 0x310, root);
    put(data, 0x420, translation);
    put(data, 0x430, rotation);
    put(data, 0x440, scale);
    memory.map(0x5000, data);

    PageTableWalker walker(memory, {4, {{0x1000, 0x5000}}});
    GuestMemoryReader guest(walker, 0x1000);
    ImageFingerprint fingerprint{};
    fingerprint.time_date_stamp = 7;
    OffsetProfile profile(fingerprint, {{"actor_array_rva", 0}, {"actor_count_rva", 8},
                                              {"actor_root_offset", 0x10}, {"root_translation_offset", 0x20},
                                              {"root_rotation_offset", 0x30}, {"root_scale_offset", 0x40}});
    const auto validated = profile.validate(fingerprint);
    assert(validated.has_value());
    UnrealAdapter adapter(guest, 0x400000, *validated);
    GameSnapshot snapshot{};
    assert(adapter.snapshot(snapshot) == Error::Ok);
    assert(snapshot.epoch == 1 && snapshot.entities.size() == 1);
    assert(snapshot.entities.front().identity == actor && snapshot.entities.front().transform.translation.y == 2.0F);
}
} // namespace

int main() {
    test_protocol_layout_and_bounds();
    test_four_level_large_page();
    test_five_level_walk();
    test_scatter_coalescing();
    test_process_lifecycle();
    test_fingerprint_gate();
    test_nonce_handshake();
    test_discovery_and_module_transport();
    test_transport_scatter_read();
    test_overlay_model_and_image_rejection();
    test_guest_reader_and_unreal_adapter();
}
