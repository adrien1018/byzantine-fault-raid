cmake_minimum_required(VERSION 3.11)
project(Filesys C CXX)

SET(CMAKE_CXX_FLAGS "-g -Wall -std=c++17")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(FetchContentExclude)

# grpc
FetchContent_Declare(
  grpc
  GIT_REPOSITORY "https://github.com/grpc/grpc"
  GIT_TAG "v1.63.0"
)
set(ABSL_ENABLE_INSTALL ON)
set(ABSL_PROPAGATE_CXX_STD ON)
set(FETCHCONTENT_QUIET OFF)
FetchContent_MakeAvailable_Exclude(grpc)
set(_PROTOBUF_LIBPROTOBUF libprotobuf)
set(_REFLECTION grpc++_reflection)
set(_PROTOBUF_PROTOC $<TARGET_FILE:protoc>)
set(_GRPC_GRPCPP grpc++)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:grpc_cpp_plugin>)

# libcorrect
FetchContent_Declare(
  libcorrect
  GIT_REPOSITORY "https://github.com/quiet/libcorrect.git"
  GIT_TAG "f5a28c74fba7a99736fe49d3a5243eca29517ae9"
)
FetchContent_MakeAvailable_Exclude(libcorrect)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Proto file
get_filename_component(filesys_proto "${PROJECT_SOURCE_DIR}/protos/filesys.proto" ABSOLUTE)
get_filename_component(filesys_proto_path "${filesys_proto}" PATH)

# Generated sources
set(filesys_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/filesys.pb.cc")
set(filesys_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/filesys.pb.h")
set(filesys_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/filesys.grpc.pb.cc")
set(filesys_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/filesys.grpc.pb.h")
add_custom_command(
      OUTPUT "${filesys_proto_srcs}" "${filesys_proto_hdrs}" "${filesys_grpc_srcs}" "${filesys_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${filesys_proto_path}" -I "${grpc_SOURCE_DIR}/third_party/protobuf/src"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${filesys_proto}"
      DEPENDS "${filesys_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}/include")

file(GLOB filesys_src CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cc")
list(REMOVE_ITEM filesys_src "${CMAKE_SOURCE_DIR}/src/filesys_server.cc"
   "${CMAKE_SOURCE_DIR}/src/filesys_client.cc" "${CMAKE_SOURCE_DIR}/src/data_storage_test.cc")

add_library(filesys_helper "${filesys_src}")
target_link_libraries(filesys_helper correct crypto)

# filesys_grpc_proto
add_library(filesys_grpc_proto
  ${filesys_grpc_srcs}
  ${filesys_grpc_hdrs}
  ${filesys_proto_srcs}
  ${filesys_proto_hdrs})
target_link_libraries(filesys_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})

# Targets filesys_(client|server)
foreach(_target
    filesys_client filesys_server)
  add_executable(${_target}
    "${CMAKE_SOURCE_DIR}/src/${_target}.cc")
  target_link_libraries(${_target}
    filesys_grpc_proto
    filesys_helper
    ${_REFLECTION}
    ${_GRPC_GRPCPP}
    ${_PROTOBUF_LIBPROTOBUF})
endforeach()

file(GLOB ENCODE_SRC_FILES ${PROJECT_SOURCE_DIR}/src/encode* ${PROJECT_SOURCE_DIR}/src/signature*)
add_executable(encode_test ${ENCODE_SRC_FILES})
target_link_libraries(encode_test correct crypto)

# file(GLOB STORAGE_SRC_FILES ${PROJECT_SOURCE_DIR}/src/data_storage* ${PROJECT_SOURCE_DIR}/src/file.cc
# ${PROJECT_SOURCE_DIR}/src/signature.cc ${PROJECT_SOURCE_DIR}/src/encode_decode.cc)
# add_executable(storage_test ${STORAGE_SRC_FILES})
# target_link_libraries(storage_test correct crypto)
