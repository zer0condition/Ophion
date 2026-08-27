#include "ophion/platform/overlay.hpp"

namespace ophion::platform {

std::vector<DrawCommand> ExternalOverlayModel::build(const GameSnapshot& snapshot,
                                                       const WorldProjector& projector,
                                                       Viewport viewport) const {
    std::vector<DrawCommand> commands;
    if (viewport.width <= 0.0F || viewport.height <= 0.0F) return commands;

    for (const auto& entity : snapshot.entities) {
        ScreenPoint center{};
        if (!projector.project(entity.transform.translation, center)) continue;
        constexpr float half_width = 18.0F;
        constexpr float half_height = 36.0F;
        if (center.x + half_width < 0.0F || center.x - half_width > viewport.width ||
            center.y + half_height < 0.0F || center.y - half_height > viewport.height) continue;
        commands.push_back({DrawKind::Box, {center.x - half_width, center.y - half_height},
                            {center.x + half_width, center.y + half_height}, 0xFF40FF40U, {}});
        commands.push_back({DrawKind::Text, {center.x - half_width, center.y - half_height - 14.0F}, {},
                            0xFFFFFFFFU, std::to_string(entity.identity)});
    }
    return commands;
}

} // namespace ophion::platform
