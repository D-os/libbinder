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
#include <binder/RpcTransport.h>
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
class RpcTransport;
class FdTrigger;

constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_NEXT = 0;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL = 0xF0000000;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION = RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL;

/**
 * This represents a session (group of connections) between a client
 * and a server. Multiple connections are needed for multiple parallel "binder"
 * calls which may also have nested calls.
 */
class RpcSession final : public virtual RefBase {
public:
    // Create an RpcSession with default configuration (raw sockets).
    static sp<RpcSession> make();

    // Create an RpcSession with the given configuration. |serverRpcCertificateFormat| and
    // |serverCertificate| must have values or be nullopt simultaneously. If they have values, set
    // server certificate.
    static sp<RpcSession> make(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory);

    /**
     * Set the maximum number of incoming threads allowed to be made (for things like callbacks).
     * By default, this is 0. This must be called before setting up this connection as a client.
     * Server sessions will inherits this value from RpcServer.
     *
     * If this is called, 'shutdown' on this session must also be called.
     * Otherwise, a threadpool will leak.
     *
     * TODO(b/189955605): start these dynamically
     */
    void setMaxIncomingThreads(size_t threads);
    size_t getMaxIncomingThreads();

    /**
     * By default, the minimum of the supported versions of the client and the
     * server will be used. Usually, this API should only be used for debugging.
     */
    [[nodiscard]] bool setProtocolVersion(uint32_t version);
    std::optional<uint32_t> getProtocolVersion();

    /**
     * This should be called once per thread, matching 'join' in the remote
     * process.
     */
    [[nodiscard]] status_t setupUnixDomainClient(const char* path);

    /**
     * Connects to an RPC server at the CVD & port.
     */
    [[nodiscard]] status_t setupVsockClient(unsigned int cvd, unsigned int port);

    /**
     * Connects to an RPC server at the given address and port.
     */
    [[nodiscard]] status_t setupInetClient(const char* addr, unsigned int port);

    /**
     * Starts talking to an RPC server which has already been connected to. This
     * is expected to be used when another process has permission to connect to
     * a binder RPC service, but this process only has permission to talk to
     * that service.
     *
     * For convenience, if 'fd' is -1, 'request' will be called.
     *
     * For future compatibility, 'request' should not reference any stack data.
     */
    [[nodiscard]] status_t setupPreconnectedClient(base::unique_fd fd,
                                                   std::function<base::unique_fd()>&& request);

    /**
     * For debugging!
     *
     * Sets up an empty connection. All queries to this connection which require a
     * response will never be satisfied. All data sent here will be
     * unceremoniously cast down the bottomless pit, /dev/null.
     */
    [[nodiscard]] status_t addNullDebuggingClient();

    /**
     * Query the other side of the session for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    sp<IBinder> getRootObject();

    /**
     * Query the other side of the session for the maximum number of threads
     * it supports (maximum number of concurrent non-nested synchronous transactions)
     */
    status_t getRemoteMaxThreads(size_t* maxThreads);

    /**
     * See RpcTransportCtx::getCertificate
     */
    std::vector<uint8_t> getCertificate(RpcCertificateFormat);

    /**
     * Shuts down the service.
     *
     * For client sessions, wait can be true or false. For server sessions,
     * waiting is not currently supported (will abort).
     *
     * Warning: this is currently not active/nice (the server isn't told we're
     * shutting down). Being nicer to the server could potentially make it
     * reclaim resources faster.
     *
     * If this is called w/ 'wait' true, then this will wait for shutdown to
     * complete before returning. This will hang if it is called from the
     * session threadpool (when processing received calls).
     */
    [[nodiscard]] bool shutdownAndWait(bool wait);

    [[nodiscard]] status_t transact(const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags);

    /**
     * Generally, you should not call this, unless you are testing error
     * conditions, as this is called automatically by BpBinders when they are
     * deleted (this is also why a raw pointer is used here)
     */
    [[nodiscard]] status_t sendDecStrong(const BpBinder* binder);

    ~RpcSession();

    /**
     * Server if this session is created as part of a server (symmetrical to
     * client servers). Otherwise, nullptr.
     */
    sp<RpcServer> server();

    // internal only
    const std::unique_ptr<RpcState>& state() { return mRpcBinderState; }

private:
    friend sp<RpcSession>;
    friend RpcServer;
    friend RpcState;
    explicit RpcSession(std::unique_ptr<RpcTransportCtx> ctx);

    // for 'target', see RpcState::sendDecStrongToTarget
    [[nodiscard]] status_t sendDecStrongToTarget(uint64_t address, size_t target);

    class EventListener : public virtual RefBase {
    public:
        virtual void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) = 0;
        virtual void onSessionIncomingThreadEnded() = 0;
    };

    class WaitForShutdownListener : public EventListener {
    public:
        void onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) override;
        void onSessionIncomingThreadEnded() override;
        void waitForShutdown(std::unique_lock<std::mutex>& lock, const sp<RpcSession>& session);

    private:
        std::condition_variable mCv;
    };
    friend WaitForShutdownListener;

    struct RpcConnection : public RefBase {
        std::unique_ptr<RpcTransport> rpcTransport;

        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<pid_t> exclusiveTid;

        bool allowNested = false;
    };

    status_t readId();

    // A thread joining a server must always call these functions in order, and
    // cleanup is only programmed once into join. These are in separate
    // functions in order to allow for different locks to be taken during
    // different parts of setup.
    //
    // transfer ownership of thread (usually done while a lock is taken on the
    // structure which originally owns the thread)
    void preJoinThreadOwnership(std::thread thread);
    // pass FD to thread and read initial connection information
    struct PreJoinSetupResult {
        // Server connection object associated with this
        sp<RpcConnection> connection;
        // Status of setup
        status_t status;
    };
    PreJoinSetupResult preJoinSetup(std::unique_ptr<RpcTransport> rpcTransport);
    // join on thread passed to preJoinThreadOwnership
    static void join(sp<RpcSession>&& session, PreJoinSetupResult&& result);

    [[nodiscard]] status_t setupClient(
            const std::function<status_t(const std::vector<uint8_t>& sessionId, bool incoming)>&
                    connectAndInit);
    [[nodiscard]] status_t setupSocketClient(const RpcSocketAddress& address);
    [[nodiscard]] status_t setupOneSocketConnection(const RpcSocketAddress& address,
                                                    const std::vector<uint8_t>& sessionId,
                                                    bool incoming);
    [[nodiscard]] status_t initAndAddConnection(base::unique_fd fd,
                                                const std::vector<uint8_t>& sessionId,
                                                bool incoming);
    [[nodiscard]] status_t addIncomingConnection(std::unique_ptr<RpcTransport> rpcTransport);
    [[nodiscard]] status_t addOutgoingConnection(std::unique_ptr<RpcTransport> rpcTransport,
                                                 bool init);
    [[nodiscard]] bool setForServer(const wp<RpcServer>& server,
                                    const wp<RpcSession::EventListener>& eventListener,
                                    const std::vector<uint8_t>& sessionId);
    sp<RpcConnection> assignIncomingConnectionToThisThread(
            std::unique_ptr<RpcTransport> rpcTransport);
    [[nodiscard]] bool removeIncomingConnection(const sp<RpcConnection>& connection);

    status_t initShutdownTrigger();

    enum class ConnectionUse {
        CLIENT,
        CLIENT_ASYNC,
        CLIENT_REFCOUNT,
    };

    // Object representing exclusive access to a connection.
    class ExclusiveConnection {
    public:
        static status_t find(const sp<RpcSession>& session, ConnectionUse use,
                             ExclusiveConnection* connection);

        ~ExclusiveConnection();
        const sp<RpcConnection>& get() { return mConnection; }

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

    const std::unique_ptr<RpcTransportCtx> mCtx;

    // On the other side of a session, for each of mOutgoing here, there should
    // be one of mIncoming on the other side (and vice versa).
    //
    // For the simplest session, a single server with one client, you would
    // have:
    //  - the server has a single 'mIncoming' and a thread listening on this
    //  - the client has a single 'mOutgoing' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)

    wp<RpcServer> mForServer; // maybe null, for client sessions
    sp<WaitForShutdownListener> mShutdownListener; // used for client sessions
    wp<EventListener> mEventListener; // mForServer if server, mShutdownListener if client

    std::vector<uint8_t> mId;

    std::unique_ptr<FdTrigger> mShutdownTrigger;

    std::unique_ptr<RpcState> mRpcBinderState;

    std::mutex mMutex; // for all below

    size_t mMaxIncomingThreads = 0;
    std::optional<uint32_t> mProtocolVersion;

    std::condition_variable mAvailableConnectionCv; // for mWaitingThreads

    struct ThreadState {
        size_t mWaitingThreads = 0;
        // hint index into clients, ++ when sending an async transaction
        size_t mOutgoingOffset = 0;
        std::vector<sp<RpcConnection>> mOutgoing;
        size_t mMaxIncoming = 0;
        std::vector<sp<RpcConnection>> mIncoming;
        std::map<std::thread::id, std::thread> mThreads;
    } mConnections;
};

} // namespace android
