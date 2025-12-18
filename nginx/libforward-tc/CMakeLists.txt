cmake_minimum_required(VERSION 3.22)
project(libforward-tc)
enable_language(C)

include(ExternalProject)

option(USE_DEBUG "Build debug messages" OFF)
option(USE_PROFILE "Build profiling support" OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if (POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

# add iproute2 source
ExternalProject_Add(iproute2
    GIT_REPOSITORY https://github.com/shemminger/iproute2.git
    GIT_TAG v6.8.0
    UPDATE_DISCONNECTED true
    SOURCE_DIR libs/iproute2
    BUILD_IN_SOURCE ON
    CONFIGURE_COMMAND ./configure
    BUILD_COMMAND make -j 32
    INSTALL_COMMAND "")

# add uthash
ExternalProject_Add(uthash
    GIT_REPOSITORY https://github.com/troydhanson/uthash.git
    SOURCE_DIR libs/uthash
    UPDATE_DISCONNECTED true
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND "")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCAP REQUIRED libcap)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(LIBMNL REQUIRED libmnl)

set(C_SRC
    src/netlink_forward.c
    src/ebpf_forward.c
)

# library
add_library(forward-tc SHARED
    ${C_SRC})

add_dependencies(forward-tc iproute2 uthash)

target_include_directories(forward-tc PRIVATE
    include
    include/private
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBELF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}/libs/uthash/include
    ${CMAKE_CURRENT_BINARY_DIR}/libs/iproute2/include)

target_link_directories(forward-tc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/libs/iproute2/lib
)

target_link_libraries(forward-tc PRIVATE
    rt
    netlink
    util
    ${LIBMNL_LIBRARIES}
    ${LIBCAP_LIBRARIES}
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIBRARIES})

set_target_properties(forward-tc PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        C_STANDARD 11)
target_compile_options(forward-tc PRIVATE
	-fstack-protector-all -Wall -Wextra -ggdb -O3 -g)
#-fsanitize=undefined,address -fno-omit-frame-pointer -fstack-protector -Wall -Wextra -ggdb -O3 -g)
target_link_options(forward-tc PRIVATE
	-Wl,-no-as-needed -fstack-protector-all -Wall -Wextra -ggdb -O3 -g)
#-fsanitize=undefined,address -fno-omit-frame-pointer -fstack-protector -Wall -Wextra -ggdb -O3 -g)

#list(APPEND FORWARD_TC_DEF -DDEBUG)
#list(APPEND FORWARD_TC_DEF -DPROFILE)
if (USE_DEBUG)
	list(APPEND FORWARD_TC_DEF -DDEBUG)
endif()
if (USE_PROFILE)
	list(APPEND FORWARD_TC_DEF -DPROFILE)
endif()
target_compile_definitions(forward-tc PUBLIC ${FORWARD_TC_DEF})

set(EBPF_REDIRECT_BLOCK_SRC ${CMAKE_SOURCE_DIR}/ebpf/ebpf_redirect_block.c)
set(EBPF_REDIRECT_BLOCK_OUT ${CMAKE_BINARY_DIR}/ebpf_redirect_block.o)
add_custom_command(
    OUTPUT ${EBPF_REDIRECT_BLOCK_OUT}
    COMMAND clang -Wall -O2 -g -target bpf -c ${EBPF_REDIRECT_BLOCK_SRC} -o ${EBPF_REDIRECT_BLOCK_OUT}
    DEPENDS ${EBPF_REDIRECT_BLOCK_SRC}
    COMMENT "Compiling eBPF program: ${EBPF_REDIRECT_BLOCK_OUT}"
)
add_custom_target(ebpf_redirect_block ALL DEPENDS ${EBPF_REDIRECT_BLOCK_OUT})

# build driver application
add_executable(main.out src/main.c)
target_include_directories(main.out PUBLIC
    include)
target_link_directories(main.out PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/libs/iproute2/lib
)
target_link_libraries(main.out PUBLIC
    forward-tc)
set_target_properties(main.out PROPERTIES
    C_STANDARD 11)
target_compile_options(main.out PRIVATE
    -fstack-protector-all -O3 -Wall -Wextra -g)
#-fsanitize=address,undefined -fno-omit-frame-pointer -fstack-protector -O3 -Wall -Wextra -g)
target_link_options(main.out PRIVATE
    -fstack-protector-all -O3 -Wall -Wextra -g)
#-fsanitize=address,undefined -fno-omit-frame-pointer -fstack-protector -O3 -Wall -Wextra -g)

message(STATUS "Building with libbpf: " ${LIBBPF_LIBRARIES})
message(STATUS "Build debug messages: " ${USE_DEBUG})
message(STATUS "Build profiling: " ${USE_PROFILE})
## install binary, library, and public header
#install(TARGETS main.out DESTINATION bin)
#install(TARGETS forward-tc DESTINATION lib)
##install(FILES include/forward.h DESTINATION include)
