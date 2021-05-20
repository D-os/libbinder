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
#include <thread>

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

    /**
     * Creates an RPC server at the current port.
     */
    [[nodiscard]] bool setupVsockServer(unsigned int port);

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

    /**
     * If setup*Server has been successful, return true. Otherwise return false.
     */
    [[nodiscard]] bool hasServer();

    /**
     * If hasServer(), return the server FD. Otherwise return invalid FD.
     */
    [[nodiscard]] base::unique_fd releaseServer();

    /**
     * Set up server using an external FD previously set up by releaseServer().
     * Return false if there's already a server.
     */
    bool setupExternalServer(base::unique_fd serverFd);

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
     *
     * Holds a strong reference to the root object.
     */
    void setRootObject(const sp<IBinder>& binder);
    /**
     * Holds a weak reference to the root object.
     */
    void setRootObjectWeak(const wp<IBinder>& binder);
    sp<IBinder> getRootObject();

    /**
     * You must have at least one client session before calling this.
     *
     * If a client needs to actively terminate join, call shutdown() in a separate thread.
     *
     * At any given point, there can only be one thread calling join().
     */
    void join();

    /**
     * Shut down any existing join(). Return true if successfully shut down, false otherwise
     * (e.g. no join() is running). Will wait for the server to be fully
     * shutdown.
     *
     * TODO(b/185167543): wait for sessions to shutdown as well
     */
    [[nodiscard]] bool shutdown();

    /**
     * For debugging!
     */
    std::vector<sp<RpcSession>> listSessions();
    size_t numUninitializedSessions();

    ~RpcServer();

    // internal use only

    void onSessionTerminating(const sp<RpcSession>& session);

private:
    friend sp<RpcServer>;
    RpcServer();

    static void establishConnection(sp<RpcServer>&& server, base::unique_fd clientFd);
    bool setupSocketServer(const RpcSocketAddress& address);
    [[nodiscard]] bool acceptOne();

    bool mAgreedExperimental = false;
    size_t mMaxThreads = 1;
    base::unique_fd mServer; // socket we are accepting sessions on

    std::mutex mLock; // for below
    std::map<std::thread::id, std::thread> mConnectingThreads;
    sp<IBinder> mRootObject;
    wp<IBinder> mRootObjectWeak;
    std::map<int32_t, sp<RpcSession>> mSessions;
    int32_t mSessionIdCounter = 0;
    bool mJoinThreadRunning = false;
    std::unique_ptr<RpcSession::FdTrigger> mShutdownTrigger;
    std::condition_variable mShutdownCv;
};

} // namespace android
