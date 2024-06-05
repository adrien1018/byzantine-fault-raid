#pragma once

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <chrono>

using namespace std::chrono_literals;

template <class T>
struct AsyncResponse {
    grpc::Status status;
    T reply;
};

template <class ResponseClass, class Callback, class Rep1, class Period1>
bool WaitResponses(size_t N, grpc::CompletionQueue& cq,
                   std::vector<AsyncResponse<ResponseClass>>& response_buffer,
                   size_t minimum_success,
                   const std::chrono::duration<Rep1, Period1>& additional_wait,
                   Callback&& callback, const std::string& log_tag) {
    void* idx;
    bool ok = false;
    std::vector<uint8_t> replied(N);
    size_t num_success = 0;
    size_t num_received = 0;
    spdlog::info("{}: Waiting for {} responses", log_tag, N);
    while (cq.Next(&idx, &ok)) {
        size_t i = (size_t)idx;
        replied[i] = true;
        if (ok) num_received++;
        if (response_buffer[i].status.ok()) num_success++;
        if (log_tag.size()) {
            spdlog::info(
                "{}: Got response from server {}, ok={}, num_success={}",
                log_tag, i, response_buffer[i].status.ok(), num_success);
        }
        if (num_received - num_success > N - minimum_success) {
            cq.Shutdown();
            while (cq.Next(&idx, &ok));
            break; /* Too many failures. */
        }
        if (num_success >= minimum_success) {
            auto deadline = std::chrono::system_clock::now() + additional_wait;
            while (cq.AsyncNext(&idx, &ok, deadline) ==
                   grpc::CompletionQueue::GOT_EVENT) {
                i = (size_t)idx;
                replied[i] = true;
                if (!response_buffer[i].status.ok()) {
                    std::cerr << response_buffer[i].status.error_message()
                              << '\n';
                }
                if (response_buffer[i].status.ok()) num_success++;
                if (log_tag.size()) {
                    spdlog::info(
                        "{}: Got response from server {}, ok={}, "
                        "num_success={}",
                        log_tag, i, response_buffer[i].status.ok(),
                        num_success);
                }
            }
            if (log_tag.size()) {
                spdlog::info("{}: Calling callback at {} successes", log_tag,
                             num_success);
            }
            if (callback(response_buffer, replied, minimum_success)) {
                if (log_tag.size()) {
                    spdlog::info("{}: Successful callback", log_tag,
                                 num_success);
                }
                cq.Shutdown();
                while (cq.Next(&idx, &ok));
                return true;
            } else {
                if (log_tag.size()) {
                    spdlog::info(
                        "{}: Callback returned false, new minimum_success={}",
                        log_tag, minimum_success);
                }
            }
        }
    }
    if (log_tag.size()) {
        spdlog::info("{}: Successful callback", log_tag, num_success);
    }
    return false;
}

/**
 * Example usage:

QueryServers<ReadBlocksReply>(
    server_list, request, &Filesys::Stub::PrepareAsyncReadBlocks,
minimum_success, 100ms, 30s,
    [&](const std::vector<AsyncResponse<ReadBlocksReply>>& responses,
        const std::vector<uint8_t>& replied,
        size_t& minimum_success) {
      return false;
    });

  * The callback will only be called when number of success >= minimum_success
  * Minimum_success can be modified in the callback
  * Return true in the callback will skip all the remaining responses
  * The whole function will return true only if callback returns true
  * additional_wait specifies the time to wait after getting minimum_success
successful responses
  */
template <class ResponseClass, class RequestClass, class Callback,
          class PrepareFunction, class Stub, class Rep1, class Period1,
          class Rep2, class Period2>
bool QueryServers(const std::vector<Stub*>& servers,
                  const RequestClass& request, PrepareFunction&& prepare,
                  size_t minimum_success,
                  const std::chrono::duration<Rep1, Period1>& additional_wait,
                  const std::chrono::duration<Rep2, Period2>& timeout,
                  Callback&& callback, const std::string& log_tag = "") {
    grpc::CompletionQueue cq;
    std::vector<AsyncResponse<ResponseClass>> response_buffer(servers.size());

    std::vector<grpc::ClientContext> contexts(servers.size());
    for (size_t i = 0; i < servers.size(); i++) {
        grpc::ClientContext& context = contexts[i];
        context.set_deadline(std::chrono::system_clock::now() + timeout);
        std::unique_ptr<grpc::ClientAsyncResponseReader<ResponseClass>>
            response_header = (servers[i]->*prepare)(&context, request, &cq);
        response_header->StartCall();
        response_header->Finish(&response_buffer[i].reply,
                                &response_buffer[i].status, (void*)i);
    }
    spdlog::info("{}: Requests sent, waiting for responses", log_tag);

    return WaitResponses<ResponseClass>(
        servers.size(), cq, response_buffer, minimum_success, additional_wait,
        std::forward<Callback>(callback), log_tag);
}

template <class ResponseClass, class RequestClass, class Callback,
          class PrepareFunction, class Stub, class Rep1, class Period1,
          class Rep2, class Period2>
bool QueryServers(const std::vector<Stub*>& servers,
                  const std::vector<RequestClass>& requests,
                  PrepareFunction&& prepare, size_t minimum_success,
                  const std::chrono::duration<Rep1, Period1>& additional_wait,
                  const std::chrono::duration<Rep2, Period2>& timeout,
                  Callback&& callback, const std::string& log_tag = "") {
    grpc::CompletionQueue cq;
    std::vector<AsyncResponse<ResponseClass>> response_buffer(servers.size());
    for (size_t i = 0; i < servers.size(); i++) {
        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + timeout);
        std::unique_ptr<grpc::ClientAsyncResponseReader<ResponseClass>>
            response_header =
                (servers[i]->*prepare)(&context, requests[i], &cq);
        response_header->StartCall();
        response_header->Finish(&response_buffer[i].reply,
                                &response_buffer[i].status, (void*)i);
    }

    return WaitResponses<ResponseClass>(
        servers.size(), cq, response_buffer, minimum_success, additional_wait,
        std::forward<Callback>(callback), log_tag);
}
