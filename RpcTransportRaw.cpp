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
    Result<size_t> peek(void *buf, size_t size) override {
        ssize_t ret = TEMP_FAILURE_RETRY(::recv(mSocket.get(), buf, size, MSG_PEEK));
        if (ret < 0) {
            return ErrnoError() << "recv(MSG_PEEK)";
        }
        return ret;
    }

    template <typename Buffer, typename SendOrReceive>
    status_t interruptableReadOrWrite(FdTrigger* fdTrigger, Buffer buffer, size_t size,
                                      SendOrReceive sendOrReceiveFun, const char* funName,
                                      int16_t event, const std::function<status_t()>& altPoll) {
        const Buffer end = buffer + size;

        MAYBE_WAIT_IN_FLAKE_MODE;

        // Since we didn't poll, we need to manually check to see if it was triggered. Otherwise, we
        // may never know we should be shutting down.
        if (fdTrigger->isTriggered()) {
            return DEAD_OBJECT;
        }

        bool havePolled = false;
        while (true) {
            ssize_t processSize = TEMP_FAILURE_RETRY(
                    sendOrReceiveFun(mSocket.get(), buffer, end - buffer, MSG_NOSIGNAL));

            if (processSize < 0) {
                int savedErrno = errno;

                // Still return the error on later passes, since it would expose
                // a problem with polling
                if (havePolled ||
                    (!havePolled && savedErrno != EAGAIN && savedErrno != EWOULDBLOCK)) {
                    LOG_RPC_DETAIL("RpcTransport %s(): %s", funName, strerror(savedErrno));
                    return -savedErrno;
                }
            } else if (processSize == 0) {
                return DEAD_OBJECT;
            } else {
                buffer += processSize;
                if (buffer == end) {
                    return OK;
                }
            }

            if (altPoll) {
                if (status_t status = altPoll(); status != OK) return status;
                if (fdTrigger->isTriggered()) {
                    return DEAD_OBJECT;
                }
            } else {
                if (status_t status = fdTrigger->triggerablePoll(mSocket.get(), event);
                    status != OK)
                    return status;
                if (!havePolled) havePolled = true;
            }
        }
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, const void* data, size_t size,
                                     const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, reinterpret_cast<const uint8_t*>(data), size,
                                        send, "send", POLLOUT, altPoll);
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, void* data, size_t size,
                                    const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, reinterpret_cast<uint8_t*>(data), size, recv,
                                        "recv", POLLIN, altPoll);
    }

private:
    base::unique_fd mSocket;
};

// RpcTransportCtx with TLS disabled.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd, FdTrigger*) const {
        return std::make_unique<RpcTransportRaw>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
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
