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

#define LOG_TAG "RpcSession"

#include <binder/RpcSession.h>

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

RpcSession::RpcSession() {
    LOG_RPC_DETAIL("RpcSession created %p", this);

    mState = std::make_unique<RpcState>();
}
RpcSession::~RpcSession() {
    LOG_RPC_DETAIL("RpcSession destroyed %p", this);

    std::lock_guard<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(mServers.size() != 0,
                        "Should not be able to destroy a session with servers in use.");
}

sp<RpcSession> RpcSession::make() {
    return sp<RpcSession>::make();
}

bool RpcSession::setupUnixDomainClient(const char* path) {
    return setupSocketClient(UnixSocketAddress(path));
}

#ifdef __BIONIC__

bool RpcSession::setupVsockClient(unsigned int cid, unsigned int port) {
    return setupSocketClient(VsockSocketAddress(cid, port));
}

#endif // __BIONIC__

bool RpcSession::setupInetClient(const char* addr, unsigned int port) {
    auto aiStart = InetSocketAddress::getAddrInfo(addr, port);
    if (aiStart == nullptr) return false;
    for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
        InetSocketAddress socketAddress(ai->ai_addr, ai->ai_addrlen, addr, port);
        if (setupSocketClient(socketAddress)) return true;
    }
    ALOGE("None of the socket address resolved for %s:%u can be added as inet client.", addr, port);
    return false;
}

bool RpcSession::addNullDebuggingClient() {
    unique_fd serverFd(TEMP_FAILURE_RETRY(open("/dev/null", O_WRONLY | O_CLOEXEC)));

    if (serverFd == -1) {
        ALOGE("Could not connect to /dev/null: %s", strerror(errno));
        return false;
    }

    addClient(std::move(serverFd));
    return true;
}

sp<IBinder> RpcSession::getRootObject() {
    ExclusiveConnection connection(sp<RpcSession>::fromExisting(this), ConnectionUse::CLIENT);
    return state()->getRootObject(connection.fd(), sp<RpcSession>::fromExisting(this));
}

status_t RpcSession::getMaxThreads(size_t* maxThreads) {
    ExclusiveConnection connection(sp<RpcSession>::fromExisting(this), ConnectionUse::CLIENT);
    return state()->getMaxThreads(connection.fd(), sp<RpcSession>::fromExisting(this), maxThreads);
}

status_t RpcSession::transact(const RpcAddress& address, uint32_t code, const Parcel& data,
                              Parcel* reply, uint32_t flags) {
    ExclusiveConnection connection(sp<RpcSession>::fromExisting(this),
                                   (flags & IBinder::FLAG_ONEWAY) ? ConnectionUse::CLIENT_ASYNC
                                                                  : ConnectionUse::CLIENT);
    return state()->transact(connection.fd(), address, code, data,
                             sp<RpcSession>::fromExisting(this), reply, flags);
}

status_t RpcSession::sendDecStrong(const RpcAddress& address) {
    ExclusiveConnection connection(sp<RpcSession>::fromExisting(this),
                                   ConnectionUse::CLIENT_REFCOUNT);
    return state()->sendDecStrong(connection.fd(), address);
}

status_t RpcSession::readId() {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mForServer != nullptr, "Can only update ID for client.");
    }

    int32_t id;

    ExclusiveConnection connection(sp<RpcSession>::fromExisting(this), ConnectionUse::CLIENT);
    status_t status =
            state()->getSessionId(connection.fd(), sp<RpcSession>::fromExisting(this), &id);
    if (status != OK) return status;

    LOG_RPC_DETAIL("RpcSession %p has id %d", this, id);
    mId = id;
    return OK;
}

void RpcSession::startThread(unique_fd client) {
    std::lock_guard<std::mutex> _l(mMutex);
    sp<RpcSession> holdThis = sp<RpcSession>::fromExisting(this);
    int fd = client.release();
    auto thread = std::thread([=] {
        holdThis->join(unique_fd(fd));
        {
            std::lock_guard<std::mutex> _l(holdThis->mMutex);
            size_t erased = mThreads.erase(std::this_thread::get_id());
            LOG_ALWAYS_FATAL_IF(erased != 0, "Could not erase thread.");
        }
    });
    mThreads[thread.get_id()] = std::move(thread);
}

void RpcSession::join(unique_fd client) {
    // must be registered to allow arbitrary client code executing commands to
    // be able to do nested calls (we can't only read from it)
    sp<RpcConnection> connection = assignServerToThisThread(std::move(client));

    while (true) {
        status_t error =
                state()->getAndExecuteCommand(connection->fd, sp<RpcSession>::fromExisting(this));

        if (error != OK) {
            ALOGI("Binder connection thread closing w/ status %s", statusToString(error).c_str());
            break;
        }
    }

    LOG_ALWAYS_FATAL_IF(!removeServerConnection(connection),
                        "bad state: connection object guaranteed to be in list");
}

wp<RpcServer> RpcSession::server() {
    return mForServer;
}

bool RpcSession::setupSocketClient(const RpcSocketAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mClients.size() != 0,
                            "Must only setup session once, but already has %zu clients",
                            mClients.size());
    }

    if (!setupOneSocketClient(addr, RPC_SESSION_ID_NEW)) return false;

    // TODO(b/185167543): we should add additional sessions dynamically
    // instead of all at once.
    // TODO(b/186470974): first risk of blocking
    size_t numThreadsAvailable;
    if (status_t status = getMaxThreads(&numThreadsAvailable); status != OK) {
        ALOGE("Could not get max threads after initial session to %s: %s", addr.toString().c_str(),
              statusToString(status).c_str());
        return false;
    }

    if (status_t status = readId(); status != OK) {
        ALOGE("Could not get session id after initial session to %s; %s", addr.toString().c_str(),
              statusToString(status).c_str());
        return false;
    }

    // we've already setup one client
    for (size_t i = 0; i + 1 < numThreadsAvailable; i++) {
        // TODO(b/185167543): avoid race w/ accept4 not being called on server
        for (size_t tries = 0; tries < 5; tries++) {
            if (setupOneSocketClient(addr, mId.value())) break;
            usleep(10000);
        }
    }

    return true;
}

bool RpcSession::setupOneSocketClient(const RpcSocketAddress& addr, int32_t id) {
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

    if (sizeof(id) != TEMP_FAILURE_RETRY(write(serverFd.get(), &id, sizeof(id)))) {
        int savedErrno = errno;
        ALOGE("Could not write id to socket at %s: %s", addr.toString().c_str(),
              strerror(savedErrno));
        return false;
    }

    LOG_RPC_DETAIL("Socket at %s client with fd %d", addr.toString().c_str(), serverFd.get());

    addClient(std::move(serverFd));
    return true;
}

void RpcSession::addClient(unique_fd fd) {
    std::lock_guard<std::mutex> _l(mMutex);
    sp<RpcConnection> session = sp<RpcConnection>::make();
    session->fd = std::move(fd);
    mClients.push_back(session);
}

void RpcSession::setForServer(const wp<RpcServer>& server, int32_t sessionId) {
    mId = sessionId;
    mForServer = server;
}

sp<RpcSession::RpcConnection> RpcSession::assignServerToThisThread(unique_fd fd) {
    std::lock_guard<std::mutex> _l(mMutex);
    sp<RpcConnection> session = sp<RpcConnection>::make();
    session->fd = std::move(fd);
    session->exclusiveTid = gettid();
    mServers.push_back(session);

    return session;
}

bool RpcSession::removeServerConnection(const sp<RpcConnection>& connection) {
    std::lock_guard<std::mutex> _l(mMutex);
    if (auto it = std::find(mServers.begin(), mServers.end(), connection); it != mServers.end()) {
        mServers.erase(it);
        return true;
    }
    return false;
}

RpcSession::ExclusiveConnection::ExclusiveConnection(const sp<RpcSession>& session,
                                                     ConnectionUse use)
      : mSession(session) {
    pid_t tid = gettid();
    std::unique_lock<std::mutex> _l(mSession->mMutex);

    mSession->mWaitingThreads++;
    while (true) {
        sp<RpcConnection> exclusive;
        sp<RpcConnection> available;

        // CHECK FOR DEDICATED CLIENT SOCKET
        //
        // A server/looper should always use a dedicated session if available
        findConnection(tid, &exclusive, &available, mSession->mClients, mSession->mClientsOffset);

        // WARNING: this assumes a server cannot request its client to send
        // a transaction, as mServers is excluded below.
        //
        // Imagine we have more than one thread in play, and a single thread
        // sends a synchronous, then an asynchronous command. Imagine the
        // asynchronous command is sent on the first client connection. Then, if
        // we naively send a synchronous command to that same connection, the
        // thread on the far side might be busy processing the asynchronous
        // command. So, we move to considering the second available thread
        // for subsequent calls.
        if (use == ConnectionUse::CLIENT_ASYNC && (exclusive != nullptr || available != nullptr)) {
            mSession->mClientsOffset = (mSession->mClientsOffset + 1) % mSession->mClients.size();
        }

        // USE SERVING SOCKET (for nested transaction)
        //
        // asynchronous calls cannot be nested
        if (use != ConnectionUse::CLIENT_ASYNC) {
            // server connections are always assigned to a thread
            findConnection(tid, &exclusive, nullptr /*available*/, mSession->mServers,
                           0 /* index hint */);
        }

        // if our thread is already using a session, prioritize using that
        if (exclusive != nullptr) {
            mConnection = exclusive;
            mReentrant = true;
            break;
        } else if (available != nullptr) {
            mConnection = available;
            mConnection->exclusiveTid = tid;
            break;
        }

        // in regular binder, this would usually be a deadlock :)
        LOG_ALWAYS_FATAL_IF(mSession->mClients.size() == 0,
                            "Not a client of any session. You must create a session to an "
                            "RPC server to make any non-nested (e.g. oneway or on another thread) "
                            "calls.");

        LOG_RPC_DETAIL("No available session (have %zu clients and %zu servers). Waiting...",
                       mSession->mClients.size(), mSession->mServers.size());
        mSession->mAvailableConnectionCv.wait(_l);
    }
    mSession->mWaitingThreads--;
}

void RpcSession::ExclusiveConnection::findConnection(pid_t tid, sp<RpcConnection>* exclusive,
                                                     sp<RpcConnection>* available,
                                                     std::vector<sp<RpcConnection>>& sockets,
                                                     size_t socketsIndexHint) {
    LOG_ALWAYS_FATAL_IF(sockets.size() > 0 && socketsIndexHint >= sockets.size(),
                        "Bad index %zu >= %zu", socketsIndexHint, sockets.size());

    if (*exclusive != nullptr) return; // consistent with break below

    for (size_t i = 0; i < sockets.size(); i++) {
        sp<RpcConnection>& socket = sockets[(i + socketsIndexHint) % sockets.size()];

        // take first available session (intuition = caching)
        if (available && *available == nullptr && socket->exclusiveTid == std::nullopt) {
            *available = socket;
            continue;
        }

        // though, prefer to take session which is already inuse by this thread
        // (nested transactions)
        if (exclusive && socket->exclusiveTid == tid) {
            *exclusive = socket;
            break; // consistent with return above
        }
    }
}

RpcSession::ExclusiveConnection::~ExclusiveConnection() {
    // reentrant use of a session means something less deep in the call stack
    // is using this fd, and it retains the right to it. So, we don't give up
    // exclusive ownership, and no thread is freed.
    if (!mReentrant) {
        std::unique_lock<std::mutex> _l(mSession->mMutex);
        mConnection->exclusiveTid = std::nullopt;
        if (mSession->mWaitingThreads > 0) {
            _l.unlock();
            mSession->mAvailableConnectionCv.notify_one();
        }
    }
}

} // namespace android
