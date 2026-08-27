#pragma once

#include "ophion/platform/adapters.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ophion::platform {

struct ScreenPoint { float x{}; float y{}; };
struct Viewport { float width{}; float height{}; };

enum class DrawKind : std::uint8_t { Box, Line, Text };
struct DrawCommand {
    DrawKind kind{};
    ScreenPoint a{};
    ScreenPoint b{};
    std::uint32_t rgba{0xFFFFFFFFU};
    std::string text;
};

class WorldProjector {
public:
    virtual ~WorldProjector() = default;
    [[nodiscard]] virtual bool project(const Vec3& world, ScreenPoint& screen) const = 0;
};

// Renderer-neutral external overlay model. A platform-specific D3D/DWM layer
// may consume these commands, but this library never hooks or loads into a game.
class ExternalOverlayModel {
public:
    [[nodiscard]] std::vector<DrawCommand> build(const GameSnapshot& snapshot,
                                                   const WorldProjector& projector,
                                                   Viewport viewport) const;
};

} // namespace ophion::platform
