SET (CMAKE_C_COMPILER             "/usr/bin/clang-12")

cmake_minimum_required(VERSION 2.8.12)

project(ebpf_xdp)

add_executable(${PROJECT_NAME} xdp.c)
target_link_libraries(${PROJECT_NAME} elf z ${libbpf_project})

SET(CMAKE_C_FLAGS "-v -g")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
include_directories(/usr/include)

#SET(CMAKE_C_FLAGS_BPF "-g -target bpf")
#SET(BPF_PROJECT ${PROJECT_NAME}_bpf.o)
#add_library(${BPF_PROJECT} OBJECT xdp.bpf.c)
#target_compile_options(${BPF_PROJECT} PRIVATE -target bpf)
#target_link_libraries(${BPF_PROJECT} elf z ${libbpf_project})

#message(EBPF_PROJECT_ROOT: ${EBPF_PROJECT_ROOT})
#install(FILES   $<TARGET_OBJECTS:${BPF_PROJECT}> DESTINATION ${EBPF_PROJECT_ROOT}/build/bin)
install(TARGETS ${PROJECT_NAME} DESTINATION ${EBPF_PROJECT_ROOT}/build/bin)
