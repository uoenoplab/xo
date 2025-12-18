cmake_minimum_required(VERSION 3.22)
project(xo-server)
enable_language(C)

include(ExternalProject)
include(FetchContent)

include(${CMAKE_SOURCE_DIR}/cmake/modules/Findlibrados2.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/modules/FindProtobufC.cmake)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

option(USE_ASYNC_WRITE "Build using rados aio for write" OFF)
option(USE_ASYNC_READ "Build using rados aio for read" OFF)
option(USE_MIGRATION "Build migration support" OFF)

FetchContent_Declare(llhttp
    URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v8.1.0.tar.gz")

set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
FetchContent_MakeAvailable(llhttp)

# add libforward source
ExternalProject_Add(libforward-tc
    URL ../../../../libforward-tc.tgz
    SOURCE_DIR libs/libforward-tc
    UPDATE_DISCONNECTED true
    GIT_TAG main
    #BUILD_IN_SOURCE ON
    #CONFIGURE_COMMAND ./configure
    #BUILD_COMMAND make -j 32
    INSTALL_COMMAND "")

## Link with the llhttp_static target
#target_link_libraries(${EXAMPLE_PROJECT_NAME} ${PROJECT_LIBRARIES} llhttp_static ${PROJECT_NAME})

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

if (POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

set(C_SRC
    src/http_client.c
    src/object_store.c
    src/handoff.c
    src/queue.c
    src/md5.c
    src/util.c
)

#add_library(demo_protobuf ${PROTO_SRC} ${PROTO_HEAD})

find_package(LibXml2 REQUIRED)
find_package(librados2 REQUIRED)
find_package(uriparser REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(INIH REQUIRED inih)
pkg_check_modules(PROTOBUF-C REQUIRED libprotobuf-c)

find_program(Protobuf_PROTOC-C_EXECUTABLE
    NAMES protoc-c
    DOC "The Google Protocol Buffers Compiler C"
    PATHS
    ${Protobuf_SRC_ROOT_FOLDER}/vsprojects/${_PROTOBUF_ARCH_DIR}Release
    ${Protobuf_SRC_ROOT_FOLDER}/vsprojects/${_PROTOBUF_ARCH_DIR}Debug
)
mark_as_advanced(Protobuf_PROTOC-C_EXECUTABLE)
PROTOBUF_GENERATE_C(PROTO_SRC PROTO_HEAD proto/socket_serialize.proto)

# build http server library
add_library(http_server STATIC
    ${PROTO_SRC}
    ${C_SRC})

add_dependencies(http_server libforward-tc)

ExternalProject_Get_property(libforward-tc SOURCE_DIR)
target_include_directories(http_server PRIVATE
    include
    ${CMAKE_CURRENT_BINARY_DIR} # for proto
    ${SOURCE_DIR}/include
    ${URIPARSER_INCLUDE_DIR}
    ${llhttp_SOURCE_DIR}/include
    ${LIBXML2_INCLUDE_DIR}
    ${LIBRADOS2_INCLUDE_DIRS})

add_custom_command(
    OUTPUT  ${CMAKE_BINARY_DIR}/ebpf_redirect_block_load.sh
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${SOURCE_DIR}/ebpf/load.sh
            ${CMAKE_BINARY_DIR}/ebpf_redirect_block_load.sh
    DEPENDS libforward-tc
    COMMENT "Copying ebpf/load.sh to the build root directory"
)

ExternalProject_Get_property(libforward-tc BINARY_DIR)
target_link_directories(http_server PUBLIC
    ${BINARY_DIR})

add_custom_command(
    OUTPUT  ${CMAKE_BINARY_DIR}/ebpf_redirect_block.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${BINARY_DIR}/ebpf_redirect_block.o
            ${CMAKE_BINARY_DIR}/ebpf_redirect_block.o
    DEPENDS libforward-tc
    COMMENT "Copying ebpf_redirect_block.o to the build root directory"
)

add_custom_target(copy_ebpf_redirect_block ALL
    DEPENDS ${CMAKE_BINARY_DIR}/ebpf_redirect_block_load.sh
    DEPENDS ${CMAKE_BINARY_DIR}/ebpf_redirect_block.o
)

target_link_libraries(http_server PUBLIC
    llhttp_static
    uriparser::uriparser
    LibXml2::LibXml2
    OpenSSL::Crypto
    forward-tc
    ${PROTOBUF-C_LIBRARIES}
    ${LIBRADOS2_LIBRARIES})

set_target_properties(http_server PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 11)

list(APPEND HTTP_SERVER_DEF -DDEBUG)
if (USE_ASYNC_WRITE)
	list(APPEND HTTP_SERVER_DEF -DASYNC_WRITE)
endif()
if (USE_ASYNC_READ)
	list(APPEND HTTP_SERVER_DEF -DASYNC_READ)
endif()
if (USE_MIGRATION)
	list(APPEND HTTP_SERVER_DEF -DUSE_MIGRATION)
endif()

target_compile_definitions(http_server PUBLIC ${HTTP_SERVER_DEF})
target_compile_options(http_server PRIVATE
    -fstack-protector-all -Wall -Wextra -ggdb -O3 -g)
#-fsanitize=undefined,address -fno-omit-frame-pointer -fstack-protector -Wall -Wextra -ggdb -O3 -g)
target_link_options(http_server PRIVATE
    -fstack-protector-all -Wall -Wextra -ggdb -O3 -g)
#-fsanitize=undefined,address -fno-omit-frame-pointer -fstack-protector -Wall -Wextra -ggdb -O3 -g)

# build driver application
add_executable(server.out src/server.c src/tls.c)

add_dependencies(server.out libforward-tc http_server)

target_include_directories(server.out PUBLIC
    ${SOURCE_DIR}/include
    ${llhttp_SOURCE_DIR}/include
    ${INIH_INCLUDE_DIRS}
    ${LIBXML2_INCLUDE_DIR}
    include)

target_link_libraries(server.out PUBLIC
    zlog
    llhttp_static
    http_server
    ${INIH_LIBRARIES}
    #efence
    OpenSSL::Crypto
    OpenSSL::SSL)

set_target_properties(server.out PROPERTIES
    C_STANDARD 11)

target_compile_options(server.out PRIVATE
    ${INIH_CFLAGS_OTHER}
    -fstack-protector-strong -O3 -Wall -Wextra -g)
#-fsanitize=address,undefined -fno-omit-frame-pointer -fstack-protector-strong -O3 -Wall -Wextra -g)
target_link_options(server.out PRIVATE
    -fstack-protector-strong -O3 -Wall -Wextra -g)
#-fsanitize=address,undefined -fno-omit-frame-pointer -fstack-protector-strong -O3 -Wall -Wextra -g)

## install binary, library, and public header
#install(TARGETS s3_benchmark.out DESTINATION bin)
#install(TARGETS benchmark DESTINATION lib)
#install(FILES include/benchmark.hh DESTINATION include)

file(COPY ${CMAKE_SOURCE_DIR}/assets DESTINATION ${CMAKE_BINARY_DIR})

message(STATUS "Building xo server binary")
message(STATUS "Build with rados aio for write: " ${USE_ASYNC_WRITE})
message(STATUS "Build with rados aio for read: " ${USE_ASYNC_READ})
message(STATUS "Build with connection migration support: " ${USE_MIGRATION})

# uninstall target
#if(NOT TARGET uninstall)
#  configure_file(
#    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
#    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
#    IMMEDIATE @ONLY)
#
#  add_custom_target(uninstall
#    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
#endif()
