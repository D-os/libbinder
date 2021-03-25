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

#include <binder/Parcel.h>
#include <binder/Stability.h>

#include "RpcState.h"
#include "RpcWireFormat.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__GLIBC__)
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
}

sp<RpcConnection> RpcConnection::make() {
    return new RpcConnection;
}

bool RpcConnection::setupUnixDomainServer(const char* path) {
    LOG_ALWAYS_FATAL_IF(mServer.get() != -1, "Only supports one server now");

    unique_fd serverFd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return false;
    }

    struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
    };

    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd.get(), (struct sockaddr*)&addr, sizeof(addr)))) {
        ALOGE("Could not bind socket at %s: %s", path, strerror(errno));
        return false;
    }

    if (0 != TEMP_FAILURE_RETRY(listen(serverFd.get(), 1 /*backlog*/))) {
        ALOGE("Could not listen socket at %s: %s", path, strerror(errno));
        return false;
    }

    mServer = std::move(serverFd);
    return true;
}

bool RpcConnection::addUnixDomainClient(const char* path) {
    LOG_RPC_DETAIL("Connecting on path: %s", path);

    unique_fd serverFd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return false;
    }

    struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
    };

    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    if (0 != TEMP_FAILURE_RETRY(connect(serverFd.get(), (struct sockaddr*)&addr, sizeof(addr)))) {
        ALOGE("Could not connect socket at %s: %s", path, strerror(errno));
        return false;
    }

    LOG_RPC_DETAIL("Unix domain client with fd %d", serverFd.get());

    addClient(std::move(serverFd));
    return true;
}

sp<IBinder> RpcConnection::getRootObject() {
    ExclusiveSocket socket(this, SocketUse::CLIENT);
    return state()->getRootObject(socket.fd(), this);
}

status_t RpcConnection::transact(const RpcAddress& address, uint32_t code, const Parcel& data,
                                 Parcel* reply, uint32_t flags) {
    ExclusiveSocket socket(this,
                           (flags & IBinder::FLAG_ONEWAY) ? SocketUse::CLIENT_ASYNC
                                                          : SocketUse::CLIENT);
    return state()->transact(socket.fd(), address, code, data, this, reply, flags);
}

status_t RpcConnection::sendDecStrong(const RpcAddress& address) {
    ExclusiveSocket socket(this, SocketUse::CLIENT_REFCOUNT);
    return state()->sendDecStrong(socket.fd(), address);
}

void RpcConnection::join() {
    // establish a connection
    {
        struct sockaddr_un clientSa;
        socklen_t clientSaLen = sizeof(clientSa);

        unique_fd clientFd(TEMP_FAILURE_RETRY(
                accept4(mServer.get(), (struct sockaddr*)&clientSa, &clientSaLen, SOCK_CLOEXEC)));
        if (clientFd < 0) {
            // If this log becomes confusing, should save more state from setupUnixDomainServer
            // in order to output here.
            ALOGE("Could not accept4 socket: %s", strerror(errno));
            return;
        }

        LOG_RPC_DETAIL("accept4 on fd %d yields fd %d", mServer.get(), clientFd.get());

        addServer(std::move(clientFd));
    }

    // We may not use the connection we just established (two threads might
    // establish connections for each other), but for now, just use one
    // server/socket connection.
    ExclusiveSocket socket(this, SocketUse::SERVER);

    while (true) {
        status_t error = state()->getAndExecuteCommand(socket.fd(), this);

        if (error != OK) {
            ALOGI("Binder socket thread closing w/ status %s", statusToString(error).c_str());
            return;
        }
    }
}

void RpcConnection::setForServer(const wp<RpcServer>& server) {
    mForServer = server;
}

wp<RpcServer> RpcConnection::server() {
    return mForServer;
}

void RpcConnection::addClient(base::unique_fd&& fd) {
    std::lock_guard<std::mutex> _l(mSocketMutex);
    sp<ConnectionSocket> connection = new ConnectionSocket();
    connection->fd = std::move(fd);
    mClients.push_back(connection);
}

void RpcConnection::addServer(base::unique_fd&& fd) {
    std::lock_guard<std::mutex> _l(mSocketMutex);
    sp<ConnectionSocket> connection = new ConnectionSocket();
    connection->fd = std::move(fd);
    mServers.push_back(connection);
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
        // A server/looper should always use a dedicated connection.
        if (use != SocketUse::SERVER) {
            findSocket(tid, &exclusive, &available, mConnection->mClients,
                       mConnection->mClientsOffset);

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
        }

        // USE SERVING SOCKET (to start serving or for nested transaction)
        //
        // asynchronous calls cannot be nested
        if (use != SocketUse::CLIENT_ASYNC) {
            // servers should start serving on an available thread only
            // otherwise, this should only be a nested call
            bool useAvailable = use == SocketUse::SERVER;

            findSocket(tid, &exclusive, (useAvailable ? &available : nullptr),
                       mConnection->mServers, 0 /* index hint */);
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

        LOG_ALWAYS_FATAL_IF(use == SocketUse::SERVER, "Must create connection to join one.");

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
