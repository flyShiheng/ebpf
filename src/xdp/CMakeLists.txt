SET (CMAKE_C_COMPILER             "/usr/bin/clang-12")

cmake_minimum_required(VERSION 2.8.12)

project(ebpf_xdp)

add_executable(${PROJECT_NAME} xdp.c)
target_link_libraries(${PROJECT_NAME} elf z ${libbpf_project})

SET(CMAKE_C_FLAGS "-v -g -target bpf")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
include_directories(/usr/include)
add_library(${PROJECT_NAME}_bpf OBJECT xdp.bpf.c)

target_link_libraries(${PROJECT_NAME}_bpf elf z ${libbpf_project})

message(EBPF_PROJECT_ROOT: ${EBPF_PROJECT_ROOT})
install(TARGETS ${PROJECT_NAME}_bpf DESTINATION ${EBPF_PROJECT_ROOT}/build/)
install(TARGETS ${PROJECT_NAME} DESTINATION ${EBPF_PROJECT_ROOT}/build/)