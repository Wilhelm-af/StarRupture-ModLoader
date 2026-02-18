cmake_minimum_required(VERSION 3.20)
project(StarRuptureMods LANGUAGES C CXX)

# Made by Wilhelm-af
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Static link libgcc/libstdc++ so the DLLs have no mingw runtime dependencies
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -Wl,--subsystem,windows:6.0")

# Strip symbols in Release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -s")
endif()

# Made by Wilhelm-af
add_subdirectory(loader)
