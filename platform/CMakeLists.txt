cmake_minimum_required(VERSION 3.20)
project(OphionPlatform LANGUAGES CXX)

add_library(ophion_platform STATIC
    src/adapters.cpp
    src/discovery.cpp
    src/internal.cpp
    src/memory.cpp
    src/overlay.cpp
    src/protocol.cpp
    src/transport.cpp)
target_compile_features(ophion_platform PUBLIC cxx_std_20)
target_include_directories(ophion_platform PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(ophion_platform PRIVATE $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)

option(OPHION_PLATFORM_BUILD_TESTS "Build deterministic platform unit tests" ON)
if (OPHION_PLATFORM_BUILD_TESTS)
    include(CTest)
    if (BUILD_TESTING)
        add_executable(ophion_platform_tests tests/platform_tests.cpp)
        target_link_libraries(ophion_platform_tests PRIVATE ophion_platform)
        add_test(NAME ophion_platform_tests COMMAND ophion_platform_tests)
    endif()
endif()
