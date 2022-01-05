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

#include <functional>
#include <memory>
#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>
#include <utils/Errors.h>

#include <binder/RpcCertificateFormat.h>

#include <sys/uio.h>

namespace android {

class FdTrigger;

// Represents a socket connection.
// No thread-safety is guaranteed for these APIs.
class RpcTransport {
public:
    virtual ~RpcTransport() = default;

    // replacement of ::recv(MSG_PEEK). Error code may not be set if TLS is enabled.
    [[nodiscard]] virtual android::base::Result<size_t> peek(void *buf, size_t size) = 0;

    /**
     * Read (or write), but allow to be interrupted by a trigger.
     *
     * iovs - array of iovecs to perform the operation on. The elements
     * of the array may be modified by this method.
     *
     * altPoll - function to be called instead of polling, when needing to wait
     * to read/write data. If this returns an error, that error is returned from
     * this function.
     *
     * Return:
     *   OK - succeeded in completely processing 'size'
     *   error - interrupted (failure or trigger)
     */
    [[nodiscard]] virtual status_t interruptableWriteFully(
            FdTrigger *fdTrigger, iovec *iovs, size_t niovs,
            const std::function<status_t()> &altPoll) = 0;
    [[nodiscard]] virtual status_t interruptableReadFully(
            FdTrigger *fdTrigger, iovec *iovs, size_t niovs,
            const std::function<status_t()> &altPoll) = 0;

protected:
    RpcTransport() = default;
};

// Represents the context that generates the socket connection.
// All APIs are thread-safe. See RpcTransportCtxRaw and RpcTransportCtxTls for details.
class RpcTransportCtx {
public:
    virtual ~RpcTransportCtx() = default;

    // Create a new RpcTransport object.
    //
    // Implementation details: for TLS, this function may incur I/O. |fdTrigger| may be used
    // to interrupt I/O. This function blocks until handshake is finished.
    [[nodiscard]] virtual std::unique_ptr<RpcTransport> newTransport(
            android::base::unique_fd fd, FdTrigger *fdTrigger) const = 0;

    // Return the preconfigured certificate of this context.
    //
    // Implementation details:
    // - For raw sockets, this always returns empty string.
    // - For TLS, this returns the certificate. See RpcTransportTls for details.
    [[nodiscard]] virtual std::vector<uint8_t> getCertificate(
            RpcCertificateFormat format) const = 0;

protected:
    RpcTransportCtx() = default;
};

// A factory class that generates RpcTransportCtx.
// All APIs are thread-safe.
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
