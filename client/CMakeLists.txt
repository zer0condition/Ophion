cmake_minimum_required(VERSION 3.20)
project(OphionClient LANGUAGES CXX)

if (NOT TARGET ophion_platform)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../platform ${CMAKE_CURRENT_BINARY_DIR}/platform)
endif()

add_executable(ophion_mock_client src/main.cpp)
target_compile_features(ophion_mock_client PRIVATE cxx_std_20)
target_link_libraries(ophion_mock_client PRIVATE ophion_platform)
