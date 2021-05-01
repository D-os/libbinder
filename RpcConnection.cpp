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

#define LOG_TAG "RpcConnection"

#include <binder/RpcConnection.h>

#include <inttypes.h>
#include <unistd.h>

#include <string_view>

#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <utils/String8.h>

#include "RpcSocketAddress.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

#ifdef __GLIBC__
extern "C" pid_t gettid();
#endif

namespace android {

using base::unique_fd;

RpcConnection::RpcConnection() {
    LOG_RPC_DETAIL("RpcConnection created %p", this);

    mState = std::make_unique<RpcState>();
}
RpcConnection::~RpcConnection() {
    LOG_RPC_DETAIL("RpcConnection destroyed %p", this);

    std::lock_guard<std::mutex> _l(mSocketMutex);
    LOG_ALWAYS_FATAL_IF(mServers.size() != 0,
                        "Should not be able to destroy a connection with servers in use.");
}

sp<RpcConnection> RpcConnection::make() {
    return sp<RpcConnection>::make();
}

bool RpcConnection::setupUnixDomainClient(const char* path) {
    return setupSocketClient(UnixSocketAddress(path));
}

#ifdef __BIONIC__

bool RpcConnection::setupVsockClient(unsigned int cid, unsigned int port) {
    return setupSocketClient(VsockSocketAddress(cid, port));
}

#endif // __BIONIC__

bool RpcConnection::setupInetClient(const char* addr, unsigned int port) {
    auto aiStart = InetSocketAddress::getAddrInfo(addr, port);
    if (aiStart == nullptr) return false;
    for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
        InetSocketAddress socketAddress(ai->ai_addr, ai->ai_addrlen, addr, port);
        if (setupSocketClient(socketAddress)) return true;
    }
    ALOGE("None of the socket address resolved for %s:%u can be added as inet client.", addr, port);
    return false;
}

bool RpcConnection::addNullDebuggingClient() {
    unique_fd serverFd(TEMP_FAILURE_RETRY(open("/dev/null", O_WRONLY | O_CLOEXEC)));

    if (serverFd == -1) {
        ALOGE("Could not connect to /dev/null: %s", strerror(errno));
        return false;
    }

    addClient(std::move(serverFd));
    return true;
}

sp<IBinder> RpcConnection::getRootObject() {
    ExclusiveSocket socket(sp<RpcConnection>::fromExisting(this), SocketUse::CLIENT);
    return state()->getRootObject(socket.fd(), sp<RpcConnection>::fromExisting(this));
}

status_t RpcConnection::getMaxThreads(size_t* maxThreads) {
    ExclusiveSocket socket(sp<RpcConnection>::fromExisting(this), SocketUse::CLIENT);
    return state()->getMaxThreads(socket.fd(), sp<RpcConnection>::fromExisting(this), maxThreads);
}

status_t RpcConnection::transact(const RpcAddress& address, uint32_t code, const Parcel& data,
                                 Parcel* reply, uint32_t flags) {
    ExclusiveSocket socket(sp<RpcConnection>::fromExisting(this),
                           (flags & IBinder::FLAG_ONEWAY) ? SocketUse::CLIENT_ASYNC
                                                          : SocketUse::CLIENT);
    return state()->transact(socket.fd(), address, code, data,
                             sp<RpcConnection>::fromExisting(this), reply, flags);
}

status_t RpcConnection::sendDecStrong(const RpcAddress& address) {
    ExclusiveSocket socket(sp<RpcConnection>::fromExisting(this), SocketUse::CLIENT_REFCOUNT);
    return state()->sendDecStrong(socket.fd(), address);
}

status_t RpcConnection::readId() {
    {
        std::lock_guard<std::mutex> _l(mSocketMutex);
        LOG_ALWAYS_FATAL_IF(mForServer != nullptr, "Can only update ID for client.");
    }

    int32_t id;

    ExclusiveSocket socket(sp<RpcConnection>::fromExisting(this), SocketUse::CLIENT);
    status_t status =
            state()->getConnectionId(socket.fd(), sp<RpcConnection>::fromExisting(this), &id);
    if (status != OK) return status;

    LOG_RPC_DETAIL("RpcConnection %p has id %d", this, id);
    mId = id;
    return OK;
}

void RpcConnection::join(unique_fd client) {
    // must be registered to allow arbitrary client code executing commands to
    // be able to do nested calls (we can't only read from it)
    sp<ConnectionSocket> socket = assignServerToThisThread(std::move(client));

    while (true) {
        status_t error =
                state()->getAndExecuteCommand(socket->fd, sp<RpcConnection>::fromExisting(this));

        if (error != OK) {
            ALOGI("Binder socket thread closing w/ status %s", statusToString(error).c_str());
            break;
        }
    }

    LOG_ALWAYS_FATAL_IF(!removeServerSocket(socket),
                        "bad state: socket object guaranteed to be in list");
}

wp<RpcServer> RpcConnection::server() {
    return mForServer;
}

bool RpcConnection::setupSocketClient(const RpcSocketAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mSocketMutex);
        LOG_ALWAYS_FATAL_IF(mClients.size() != 0,
                            "Must only setup connection once, but already has %zu clients",
                            mClients.size());
    }

    if (!setupOneSocketClient(addr)) return false;

    // TODO(b/185167543): we should add additional connections dynamically
    // instead of all at once.
    // TODO(b/186470974): first risk of blocking
    size_t numThreadsAvailable;
    if (status_t status = getMaxThreads(&numThreadsAvailable); status != OK) {
        ALOGE("Could not get max threads after initial connection to %s: %s",
              addr.toString().c_str(), statusToString(status).c_str());
        return false;
    }

    if (status_t status = readId(); status != OK) {
        ALOGE("Could not get connection id after initial connection to %s; %s",
              addr.toString().c_str(), statusToString(status).c_str());
        return false;
    }

    // we've already setup one client
    for (size_t i = 0; i + 1 < numThreadsAvailable; i++) {
        // TODO(b/185167543): avoid race w/ accept4 not being called on server
        for (size_t tries = 0; tries < 5; tries++) {
            if (setupOneSocketClient(addr)) break;
            usleep(10000);
        }
    }

    return true;
}

bool RpcConnection::setupOneSocketClient(const RpcSocketAddress& addr) {
    unique_fd serverFd(
            TEMP_FAILURE_RETRY(socket(addr.addr()->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        int savedErrno = errno;
        ALOGE("Could not create socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return false;
    }

    if (0 != TEMP_FAILURE_RETRY(connect(serverFd.get(), addr.addr(), addr.addrSize()))) {
        int savedErrno = errno;
        ALOGE("Could not connect socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return false;
    }

    LOG_RPC_DETAIL("Socket at %s client with fd %d", addr.toString().c_str(), serverFd.get());

    addClient(std::move(serverFd));
    return true;
}

void RpcConnection::addClient(unique_fd fd) {
    std::lock_guard<std::mutex> _l(mSocketMutex);
    sp<ConnectionSocket> connection = sp<ConnectionSocket>::make();
    connection->fd = std::move(fd);
    mClients.push_back(connection);
}

void RpcConnection::setForServer(const wp<RpcServer>& server, int32_t connectionId) {
    mId = connectionId;
    mForServer = server;
}

sp<RpcConnection::ConnectionSocket> RpcConnection::assignServerToThisThread(unique_fd fd) {
    std::lock_guard<std::mutex> _l(mSocketMutex);
    sp<ConnectionSocket> connection = sp<ConnectionSocket>::make();
    connection->fd = std::move(fd);
    connection->exclusiveTid = gettid();
    mServers.push_back(connection);

    return connection;
}

bool RpcConnection::removeServerSocket(const sp<ConnectionSocket>& socket) {
    std::lock_guard<std::mutex> _l(mSocketMutex);
    if (auto it = std::find(mServers.begin(), mServers.end(), socket); it != mServers.end()) {
        mServers.erase(it);
        return true;
    }
    return false;
}

RpcConnection::ExclusiveSocket::ExclusiveSocket(const sp<RpcConnection>& connection, SocketUse use)
      : mConnection(connection) {
    pid_t tid = gettid();
    std::unique_lock<std::mutex> _l(mConnection->mSocketMutex);

    mConnection->mWaitingThreads++;
    while (true) {
        sp<ConnectionSocket> exclusive;
        sp<ConnectionSocket> available;

        // CHECK FOR DEDICATED CLIENT SOCKET
        //
        // A server/looper should always use a dedicated connection if available
        findSocket(tid, &exclusive, &available, mConnection->mClients, mConnection->mClientsOffset);

        // WARNING: this assumes a server cannot request its client to send
        // a transaction, as mServers is excluded below.
        //
        // Imagine we have more than one thread in play, and a single thread
        // sends a synchronous, then an asynchronous command. Imagine the
        // asynchronous command is sent on the first client socket. Then, if
        // we naively send a synchronous command to that same socket, the
        // thread on the far side might be busy processing the asynchronous
        // command. So, we move to considering the second available thread
        // for subsequent calls.
        if (use == SocketUse::CLIENT_ASYNC && (exclusive != nullptr || available != nullptr)) {
            mConnection->mClientsOffset =
                    (mConnection->mClientsOffset + 1) % mConnection->mClients.size();
        }

        // USE SERVING SOCKET (for nested transaction)
        //
        // asynchronous calls cannot be nested
        if (use != SocketUse::CLIENT_ASYNC) {
            // server sockets are always assigned to a thread
            findSocket(tid, &exclusive, nullptr /*available*/, mConnection->mServers,
                       0 /* index hint */);
        }

        // if our thread is already using a connection, prioritize using that
        if (exclusive != nullptr) {
            mSocket = exclusive;
            mReentrant = true;
            break;
        } else if (available != nullptr) {
            mSocket = available;
            mSocket->exclusiveTid = tid;
            break;
        }

        // in regular binder, this would usually be a deadlock :)
        LOG_ALWAYS_FATAL_IF(mConnection->mClients.size() == 0,
                            "Not a client of any connection. You must create a connection to an "
                            "RPC server to make any non-nested (e.g. oneway or on another thread) "
                            "calls.");

        LOG_RPC_DETAIL("No available connection (have %zu clients and %zu servers). Waiting...",
                       mConnection->mClients.size(), mConnection->mServers.size());
        mConnection->mSocketCv.wait(_l);
    }
    mConnection->mWaitingThreads--;
}

void RpcConnection::ExclusiveSocket::findSocket(pid_t tid, sp<ConnectionSocket>* exclusive,
                                                sp<ConnectionSocket>* available,
                                                std::vector<sp<ConnectionSocket>>& sockets,
                                                size_t socketsIndexHint) {
    LOG_ALWAYS_FATAL_IF(sockets.size() > 0 && socketsIndexHint >= sockets.size(),
                        "Bad index %zu >= %zu", socketsIndexHint, sockets.size());

    if (*exclusive != nullptr) return; // consistent with break below

    for (size_t i = 0; i < sockets.size(); i++) {
        sp<ConnectionSocket>& socket = sockets[(i + socketsIndexHint) % sockets.size()];

        // take first available connection (intuition = caching)
        if (available && *available == nullptr && socket->exclusiveTid == std::nullopt) {
            *available = socket;
            continue;
        }

        // though, prefer to take connection which is already inuse by this thread
        // (nested transactions)
        if (exclusive && socket->exclusiveTid == tid) {
            *exclusive = socket;
            break; // consistent with return above
        }
    }
}

RpcConnection::ExclusiveSocket::~ExclusiveSocket() {
    // reentrant use of a connection means something less deep in the call stack
    // is using this fd, and it retains the right to it. So, we don't give up
    // exclusive ownership, and no thread is freed.
    if (!mReentrant) {
        std::unique_lock<std::mutex> _l(mConnection->mSocketMutex);
        mSocket->exclusiveTid = std::nullopt;
        if (mConnection->mWaitingThreads > 0) {
            _l.unlock();
            mConnection->mSocketCv.notify_one();
        }
    }
}

} // namespace android
