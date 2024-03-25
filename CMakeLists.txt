
SET (CMAKE_C_COMPILER             "/usr/bin/clang-12")
SET (CMAKE_C_FLAGS                "-Wall ${CMAKE_C_FLAGS}")
SET (CMAKE_C_FLAGS_DEBUG          "-g")
SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")

SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++-12")
SET (CMAKE_CXX_FLAGS                "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG          "-g")
SET (CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")

SET (CMAKE_AR      "/usr/bin/llvm-ar-12")
SET (CMAKE_LINKER  "/usr/bin/llvm-ld-12")
SET (CMAKE_NM      "/usr/bin/llvm-nm-12")
SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump-12")
SET (CMAKE_RANLIB  "/usr/bin/llvm-ranlib-12")

cmake_minimum_required(VERSION 2.8.12)

project(ebpf-study)

#execute_process(COMMAND git config --global --add safe.directory ${CMAKE_CURRENT_SOURCE_DIR}/src/cc/libbpf
#                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#                RESULT_VARIABLE CONFIG_RESULT)

set(libbpf_project mylibbpf)
set(EBPF_PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf)
include_directories(${LIBBPF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)

file(GLOB libbpf_sources "${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/*.c")
set(libbpf_uapi libbpf/include/uapi/linux/)

add_library(${libbpf_project} SHARED ${libbpf_sources})

target_link_libraries(${libbpf_project} elf z)

add_subdirectory(src/xdp)
