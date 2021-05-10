/*
 * Copyright (C) 2020 The Android Open Source Project
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
#pragma once

#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <binder/RpcSession.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <mutex>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

class RpcSocketAddress;

/**
 * This represents a server of an interface, which may be connected to by any
 * number of clients over sockets.
 *
 * Usage:
 *     auto server = RpcServer::make();
 *     // only supports one now
 *     if (!server->setup*Server(...)) {
 *         :(
 *     }
 *     server->join();
 */
class RpcServer final : public virtual RefBase {
public:
    static sp<RpcServer> make();

    /**
     * This represents a session for responses, e.g.:
     *
     *     process A serves binder a
     *     process B opens a session to process A
     *     process B makes binder b and sends it to A
     *     A uses this 'back session' to send things back to B
     */
    [[nodiscard]] bool setupUnixDomainServer(const char* path);

#ifdef __BIONIC__
    /**
     * Creates an RPC server at the current port.
     */
    [[nodiscard]] bool setupVsockServer(unsigned int port);
#endif // __BIONIC__

    /**
     * Creates an RPC server at the current port using IPv4.
     *
     * TODO(b/182914638): IPv6 support
     *
     * Set |port| to 0 to pick an ephemeral port; see discussion of
     * /proc/sys/net/ipv4/ip_local_port_range in ip(7). In this case, |assignedPort|
     * will be set to the picked port number, if it is not null.
     */
    [[nodiscard]] bool setupInetServer(unsigned int port, unsigned int* assignedPort);

    void iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();

    /**
     * This must be called before adding a client session.
     *
     * If this is not specified, this will be a single-threaded server.
     *
     * TODO(b/185167543): these are currently created per client, but these
     * should be shared.
     */
    void setMaxThreads(size_t threads);
    size_t getMaxThreads();

    /**
     * The root object can be retrieved by any client, without any
     * authentication. TODO(b/183988761)
     */
    void setRootObject(const sp<IBinder>& binder);
    sp<IBinder> getRootObject();

    /**
     * You must have at least one client session before calling this.
     *
     * TODO(b/185167543): way to shut down?
     */
    void join();

    /**
     * For debugging!
     */
    std::vector<sp<RpcSession>> listSessions();

    ~RpcServer();

    // internal use only

    void onSessionTerminating(const sp<RpcSession>& session);

private:
    friend sp<RpcServer>;
    RpcServer();

    bool setupSocketServer(const RpcSocketAddress& address);

    bool mAgreedExperimental = false;
    bool mStarted = false; // TODO(b/185167543): support dynamically added clients
    size_t mMaxThreads = 1;
    base::unique_fd mServer; // socket we are accepting sessions on

    std::mutex mLock; // for below
    sp<IBinder> mRootObject;
    std::map<int32_t, sp<RpcSession>> mSessions;
    int32_t mSessionIdCounter = 0;
};

} // namespace android
