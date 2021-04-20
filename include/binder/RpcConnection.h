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

#include <optional>
#include <vector>

// WARNING: This is a feature which is still in development, and it is subject
// to radical change. Any production use of this may subject your code to any
// number of problems.

namespace android {

class Parcel;
class RpcServer;
class RpcState;

/**
 * This represents a multi-threaded/multi-socket connection between a client
 * and a server.
 */
class RpcConnection final : public virtual RefBase {
public:
    static sp<RpcConnection> make();

    /**
     * This represents a connection for responses, e.g.:
     *
     *     process A serves binder a
     *     process B opens a connection to process A
     *     process B makes binder b and sends it to A
     *     A uses this 'back connection' to send things back to B
     *
     * This should be called once, and then a call should be made to join per
     * connection thread.
     */
    [[nodiscard]] bool setupUnixDomainServer(const char* path);

    /**
     * This should be called once per thread, matching 'join' in the remote
     * process.
     */
    [[nodiscard]] bool addUnixDomainClient(const char* path);

#ifdef __BIONIC__
    /**
     * Creates an RPC server at the current port.
     */
    [[nodiscard]] bool setupVsockServer(unsigned int port);

    /**
     * Connects to an RPC server at the CVD & port.
     */
    [[nodiscard]] bool addVsockClient(unsigned int cvd, unsigned int port);
#endif // __BIONIC__

    /**
     * Creates an RPC server at the current port.
     */
    [[nodiscard]] bool setupInetServer(unsigned int port);

    /**
     * Connects to an RPC server at the given address and port.
     */
    [[nodiscard]] bool addInetClient(const char* addr, unsigned int port);

    /**
     * For debugging!
     *
     * Sets up an empty socket. All queries to this socket which require a
     * response will never be satisfied. All data sent here will be
     * unceremoniously cast down the bottomless pit, /dev/null.
     */
    [[nodiscard]] bool addNullDebuggingClient();

    /**
     * Query the other side of the connection for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    sp<IBinder> getRootObject();

    [[nodiscard]] status_t transact(const RpcAddress& address, uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags);
    [[nodiscard]] status_t sendDecStrong(const RpcAddress& address);

    /**
     * Adds a server thread accepting connections. Must be called after
     * setup*Server.
     */
    void join();

    ~RpcConnection();

    void setForServer(const wp<RpcServer>& server);
    wp<RpcServer> server();

    // internal only
    const std::unique_ptr<RpcState>& state() { return mState; }

    class SocketAddress {
    public:
        virtual ~SocketAddress();
        virtual std::string toString() const = 0;
        virtual const sockaddr* addr() const = 0;
        virtual size_t addrSize() const = 0;
    };

private:
    friend sp<RpcConnection>;
    RpcConnection();

    bool setupSocketServer(const SocketAddress& address);
    bool addSocketClient(const SocketAddress& address);
    void addClient(base::unique_fd&& fd);
    void assignServerToThisThread(base::unique_fd&& fd);

    struct ConnectionSocket : public RefBase {
        base::unique_fd fd;

        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<pid_t> exclusiveTid;
    };

    enum class SocketUse {
        CLIENT,
        CLIENT_ASYNC,
        CLIENT_REFCOUNT,
        SERVER,
    };

    // RAII object for connection socket
    class ExclusiveSocket {
    public:
        explicit ExclusiveSocket(const sp<RpcConnection>& connection, SocketUse use);
        ~ExclusiveSocket();
        const base::unique_fd& fd() { return mSocket->fd; }

    private:
        static void findSocket(pid_t tid, sp<ConnectionSocket>* exclusive,
                               sp<ConnectionSocket>* available,
                               std::vector<sp<ConnectionSocket>>& sockets, size_t socketsIndexHint);

        sp<RpcConnection> mConnection; // avoid deallocation
        sp<ConnectionSocket> mSocket;

        // whether this is being used for a nested transaction (being on the same
        // thread guarantees we won't write in the middle of a message, the way
        // the wire protocol is constructed guarantees this is safe).
        bool mReentrant = false;
    };

    // On the other side of a connection, for each of mClients here, there should
    // be one of mServers on the other side (and vice versa).
    //
    // For the simplest connection, a single server with one client, you would
    // have:
    //  - the server has a single 'mServers' and a thread listening on this
    //  - the client has a single 'mClients' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)

    wp<RpcServer> mForServer; // maybe null, for client connections

    std::unique_ptr<RpcState> mState;

    base::unique_fd mServer; // socket we are accepting connections on

    std::mutex mSocketMutex;           // for all below
    std::condition_variable mSocketCv; // for mWaitingThreads
    size_t mWaitingThreads = 0;
    size_t mClientsOffset = 0; // hint index into clients, ++ when sending an async transaction
    std::vector<sp<ConnectionSocket>> mClients;
    std::vector<sp<ConnectionSocket>> mServers;
};

} // namespace android
