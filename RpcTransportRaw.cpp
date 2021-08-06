/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "RpcRawTransport"
#include <log/log.h>

#include <poll.h>

#include <binder/RpcTransportRaw.h>

#include "FdTrigger.h"
#include "RpcState.h"

using android::base::ErrnoError;
using android::base::Result;

namespace android {

namespace {

// RpcTransport with TLS disabled.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    Result<size_t> send(const void* buf, size_t size) {
        ssize_t ret = TEMP_FAILURE_RETRY(::send(mSocket.get(), buf, size, MSG_NOSIGNAL));
        if (ret < 0) {
            return ErrnoError() << "send()";
        }
        return ret;
    }
    Result<size_t> recv(void* buf, size_t size) {
        ssize_t ret = TEMP_FAILURE_RETRY(::recv(mSocket.get(), buf, size, MSG_NOSIGNAL));
        if (ret < 0) {
            return ErrnoError() << "recv()";
        }
        return ret;
    }
    Result<size_t> peek(void *buf, size_t size) override {
        ssize_t ret = TEMP_FAILURE_RETRY(::recv(mSocket.get(), buf, size, MSG_PEEK | MSG_DONTWAIT));
        if (ret < 0) {
            return ErrnoError() << "recv(MSG_PEEK)";
        }
        return ret;
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, const void* data, size_t size) override {
        const uint8_t* buffer = reinterpret_cast<const uint8_t*>(data);
        const uint8_t* end = buffer + size;

        MAYBE_WAIT_IN_FLAKE_MODE;

        status_t status;
        while ((status = fdTrigger->triggerablePoll(mSocket.get(), POLLOUT)) == OK) {
            auto writeSize = this->send(buffer, end - buffer);
            if (!writeSize.ok()) {
                LOG_RPC_DETAIL("RpcTransport::send(): %s", writeSize.error().message().c_str());
                return writeSize.error().code() == 0 ? UNKNOWN_ERROR : -writeSize.error().code();
            }

            if (*writeSize == 0) return DEAD_OBJECT;

            buffer += *writeSize;
            if (buffer == end) return OK;
        }
        return status;
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, void* data, size_t size) override {
        uint8_t* buffer = reinterpret_cast<uint8_t*>(data);
        uint8_t* end = buffer + size;

        MAYBE_WAIT_IN_FLAKE_MODE;

        status_t status;
        while ((status = fdTrigger->triggerablePoll(mSocket.get(), POLLIN)) == OK) {
            auto readSize = this->recv(buffer, end - buffer);
            if (!readSize.ok()) {
                LOG_RPC_DETAIL("RpcTransport::recv(): %s", readSize.error().message().c_str());
                return readSize.error().code() == 0 ? UNKNOWN_ERROR : -readSize.error().code();
            }

            if (*readSize == 0) return DEAD_OBJECT; // EOF

            buffer += *readSize;
            if (buffer == end) return OK;
        }
        return status;
    }

private:
    android::base::unique_fd mSocket;
};

// RpcTransportCtx with TLS disabled.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd) const {
        return std::make_unique<RpcTransportRaw>(std::move(fd));
    }
};
} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newServerCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newClientCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

const char *RpcTransportCtxFactoryRaw::toCString() const {
    return "raw";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryRaw::make() {
    return std::unique_ptr<RpcTransportCtxFactoryRaw>(new RpcTransportCtxFactoryRaw());
}

} // namespace android
