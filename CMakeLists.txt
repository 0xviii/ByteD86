cmake_minimum_required(VERSION 3.10)
project(ByteD86 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
pkg_check_modules(KEYSTONE REQUIRED keystone)

include_directories(
    ${CAPSTONE_INCLUDE_DIRS}
    ${KEYSTONE_INCLUDE_DIRS}
)

link_directories(
    ${CAPSTONE_LIBRARY_DIRS}
    ${KEYSTONE_LIBRARY_DIRS}
)

add_executable(ByteD86
    src/main.cpp
    src/disasm.cpp
    src/disasm.h
    src/patcher.cpp
    src/patcher.h
)

target_link_libraries(ByteD86
    ${CAPSTONE_LIBRARIES}
    ${KEYSTONE_LIBRARIES}
)
