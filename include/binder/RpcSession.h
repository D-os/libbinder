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
#include <binder/RpcAddress.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <optional>
#include <thread>
#include <vector>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

class Parcel;
class RpcServer;
class RpcSocketAddress;
class RpcState;

/**
 * This represents a session (group of connections) between a client
 * and a server. Multiple connections are needed for multiple parallel "binder"
 * calls which may also have nested calls.
 */
class RpcSession final : public virtual RefBase {
public:
    static sp<RpcSession> make();

    /**
     * This should be called once per thread, matching 'join' in the remote
     * process.
     */
    [[nodiscard]] bool setupUnixDomainClient(const char* path);

#ifdef __BIONIC__
    /**
     * Connects to an RPC server at the CVD & port.
     */
    [[nodiscard]] bool setupVsockClient(unsigned int cvd, unsigned int port);
#endif // __BIONIC__

    /**
     * Connects to an RPC server at the given address and port.
     */
    [[nodiscard]] bool setupInetClient(const char* addr, unsigned int port);

    /**
     * For debugging!
     *
     * Sets up an empty connection. All queries to this connection which require a
     * response will never be satisfied. All data sent here will be
     * unceremoniously cast down the bottomless pit, /dev/null.
     */
    [[nodiscard]] bool addNullDebuggingClient();

    /**
     * Query the other side of the session for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    sp<IBinder> getRootObject();

    /**
     * Query the other side of the session for the maximum number of threads
     * it supports (maximum number of concurrent non-nested synchronous transactions)
     */
    status_t getMaxThreads(size_t* maxThreads);

    [[nodiscard]] status_t transact(const RpcAddress& address, uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags);
    [[nodiscard]] status_t sendDecStrong(const RpcAddress& address);

    ~RpcSession();

    wp<RpcServer> server();

    // internal only
    const std::unique_ptr<RpcState>& state() { return mState; }

    class PrivateAccessorForId {
    private:
        friend class RpcSession;
        friend class RpcState;
        explicit PrivateAccessorForId(const RpcSession* session) : mSession(session) {}

        const std::optional<int32_t> get() { return mSession->mId; }

        const RpcSession* mSession;
    };
    PrivateAccessorForId getPrivateAccessorForId() const { return PrivateAccessorForId(this); }

private:
    friend PrivateAccessorForId;
    friend sp<RpcSession>;
    friend RpcServer;
    RpcSession();

    status_t readId();

    void startThread(base::unique_fd client);
    void join(base::unique_fd client);

    struct RpcConnection : public RefBase {
        base::unique_fd fd;

        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<pid_t> exclusiveTid;
    };

    bool setupSocketClient(const RpcSocketAddress& address);
    bool setupOneSocketClient(const RpcSocketAddress& address, int32_t sessionId);
    void addClient(base::unique_fd fd);
    void setForServer(const wp<RpcServer>& server, int32_t sessionId);
    sp<RpcConnection> assignServerToThisThread(base::unique_fd fd);
    bool removeServerConnection(const sp<RpcConnection>& connection);

    enum class ConnectionUse {
        CLIENT,
        CLIENT_ASYNC,
        CLIENT_REFCOUNT,
    };

    // RAII object for session connection
    class ExclusiveConnection {
    public:
        explicit ExclusiveConnection(const sp<RpcSession>& session, ConnectionUse use);
        ~ExclusiveConnection();
        const base::unique_fd& fd() { return mConnection->fd; }

    private:
        static void findConnection(pid_t tid, sp<RpcConnection>* exclusive,
                                   sp<RpcConnection>* available,
                                   std::vector<sp<RpcConnection>>& sockets,
                                   size_t socketsIndexHint);

        sp<RpcSession> mSession; // avoid deallocation
        sp<RpcConnection> mConnection;

        // whether this is being used for a nested transaction (being on the same
        // thread guarantees we won't write in the middle of a message, the way
        // the wire protocol is constructed guarantees this is safe).
        bool mReentrant = false;
    };

    // On the other side of a session, for each of mClients here, there should
    // be one of mServers on the other side (and vice versa).
    //
    // For the simplest session, a single server with one client, you would
    // have:
    //  - the server has a single 'mServers' and a thread listening on this
    //  - the client has a single 'mClients' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)

    wp<RpcServer> mForServer; // maybe null, for client sessions

    // TODO(b/183988761): this shouldn't be guessable
    std::optional<int32_t> mId;

    std::unique_ptr<RpcState> mState;

    std::mutex mMutex; // for all below

    std::condition_variable mAvailableConnectionCv; // for mWaitingThreads
    size_t mWaitingThreads = 0;
    size_t mClientsOffset = 0; // hint index into clients, ++ when sending an async transaction
    std::vector<sp<RpcConnection>> mClients;
    std::vector<sp<RpcConnection>> mServers;

    // TODO(b/185167543): use for reverse sessions (allow client to also
    // serve calls on a session).
    // TODO(b/185167543): allow sharing between different sessions in a
    // process? (or combine with mServers)
    std::map<std::thread::id, std::thread> mThreads;
};

} // namespace android
