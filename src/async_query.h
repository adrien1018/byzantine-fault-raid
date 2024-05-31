#pragma once

#include <grpcpp/grpcpp.h>
#include <chrono>

using namespace std::chrono_literals;

template <class T>
struct AsyncResponse {
  grpc::Status status;
  T reply;
};

/**
 * Example usage:

QueryServers<ReadBlocksReply>(
    server_list, request, &Filesys::Stub::PrepareAsyncReadBlocks, minimum_success, 30s,
    [&](const std::vector<AsyncResponse<ReadBlocksReply>>& responses,
        const std::vector<uint8_t>& replied,
        size_t recent_idx,
        size_t& minimum_success) {
      return false;
    });

  * The callback will only be called when number of success >= minimum_success
  * Minimum_success can be modified in the callback
  * Return true in the callback will skip all the remaining responses
  * The whole function will return true only if callback returns true
  */
template <class ResponseClass, class RequestClass, class Callback, class PrepareFunction, class Stub, class Rep, class Period>
bool QueryServers(
    const std::vector<Stub*>& servers,
    const RequestClass& request,
    PrepareFunction&& prepare,
    size_t minimum_success,
    const std::chrono::duration<Rep, Period>& timeout,
    Callback&& callback) {
  grpc::ClientContext context;
  grpc::CompletionQueue cq;
  std::vector<AsyncResponse<ResponseClass>> response_buffer(servers.size());
  for (size_t i = 0; i < servers.size(); i++) {
    std::unique_ptr<grpc::ClientAsyncResponseReader<ResponseClass>> response_header =
        (servers[i]->*prepare)(&context, request, &cq);
    response_header->StartCall();
    response_header->Finish(&response_buffer[i].reply,
                            &response_buffer[i].status,
                            (void*)i);
  }

  void* idx;
  bool ok = false;
  std::vector<uint8_t> replied(servers.size());
  size_t num_success = 0;
  while (cq.Next(&idx, &ok)) {
    size_t i = (size_t)idx;
    replied[i] = true;
    if (response_buffer[i].status.ok()) num_success++;
    if (num_success >= minimum_success) {
      // TODO: can we just return and ignore any ongoing requests without any cleanup?
      if (callback(response_buffer, replied, i, minimum_success)) return true;
    }
  }
  return false;
}
