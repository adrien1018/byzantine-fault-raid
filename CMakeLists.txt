cmake_minimum_required(VERSION 3.12)
project(Filesys C CXX)

SET(CMAKE_CXX_FLAGS "-Wall -std=c++17")

include(common.cmake)

# Proto file
get_filename_component(filesys_proto "${CMAKE_SOURCE_DIR}/protos/filesys.proto" ABSOLUTE)
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
        -I "${filesys_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${filesys_proto}"
      DEPENDS "${filesys_proto}")

# Include generated *.pb.h files
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}/include")

file(GLOB filesys_src CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cc")
list(REMOVE_ITEM filesys_src "${CMAKE_SOURCE_DIR}/src/filesys_server.cc"
   "${CMAKE_SOURCE_DIR}/src/filesys_client.cc")

add_library(filesys_helper "${filesys_src}")

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
  filesys_helper
  filesys_grpc_proto
  ${_REFLECTION}
  ${_GRPC_GRPCPP}
  ${_PROTOBUF_LIBPROTOBUF})
endforeach()