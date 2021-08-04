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

// Wraps the transport layer of RPC. Implementation may use plain sockets or TLS.

#pragma once

#include <memory>
#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

namespace android {

// Represents a socket connection.
class RpcTransport {
public:
    virtual ~RpcTransport() = default;

    // replacement of ::send(). errno may not be set if TLS is enabled.
    virtual android::base::Result<ssize_t> send(const void *buf, int size) = 0;

    // replacement of ::recv(). errno may not be set if TLS is enabled.
    virtual android::base::Result<ssize_t> recv(void *buf, int size) = 0;

    // replacement of ::recv(MSG_PEEK). errno may not be set if TLS is enabled.
    //
    // Implementation details:
    // - For TLS, this may invoke syscalls and read data from the transport
    // into an internal buffer in userspace. After that, pending() == true.
    // - For raw sockets, this calls ::recv(MSG_PEEK), which leaves the data in the kernel buffer;
    // pending() is always false.
    virtual android::base::Result<ssize_t> peek(void *buf, int size) = 0;

    // Returns true if there are data pending in a userspace buffer that RpcTransport holds.
    //
    // Implementation details:
    // - For TLS, this does not invoke any syscalls or read any data from the
    // transport. This only returns whether there are data pending in the internal buffer in
    // userspace.
    // - For raw sockets, this always returns false.
    virtual bool pending() = 0;

    // Returns fd for polling.
    //
    // Do not directly read / write on this raw fd!
    [[nodiscard]] virtual android::base::borrowed_fd pollSocket() const = 0;

protected:
    RpcTransport() = default;
};

// Represents the context that generates the socket connection.
class RpcTransportCtx {
public:
    virtual ~RpcTransportCtx() = default;
    [[nodiscard]] virtual std::unique_ptr<RpcTransport> newTransport(
            android::base::unique_fd fd) const = 0;

protected:
    RpcTransportCtx() = default;
};

// A factory class that generates RpcTransportCtx.
class RpcTransportCtxFactory {
public:
    virtual ~RpcTransportCtxFactory() = default;
    // Creates server context.
    [[nodiscard]] virtual std::unique_ptr<RpcTransportCtx> newServerCtx() const = 0;

    // Creates client context.
    [[nodiscard]] virtual std::unique_ptr<RpcTransportCtx> newClientCtx() const = 0;

    // Return a short description of this transport (e.g. "raw"). For logging / debugging / testing
    // only.
    [[nodiscard]] virtual const char *toCString() const = 0;

protected:
    RpcTransportCtxFactory() = default;
};

} // namespace android
