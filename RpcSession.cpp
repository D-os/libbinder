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
#include <poll.h>
#include <unistd.h>

#include <string_view>

#include <android-base/macros.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
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
    LOG_ALWAYS_FATAL_IF(mServerConnections.size() != 0,
                        "Should not be able to destroy a session with servers in use.");
}

sp<RpcSession> RpcSession::make() {
    return sp<RpcSession>::make();
}

void RpcSession::setMaxThreads(size_t threads) {
    std::lock_guard<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(!mClientConnections.empty() || !mServerConnections.empty(),
                        "Must set max threads before setting up connections, but has %zu client(s) "
                        "and %zu server(s)",
                        mClientConnections.size(), mServerConnections.size());
    mMaxThreads = threads;
}

size_t RpcSession::getMaxThreads() {
    std::lock_guard<std::mutex> _l(mMutex);
    return mMaxThreads;
}

bool RpcSession::setupUnixDomainClient(const char* path) {
    return setupSocketClient(UnixSocketAddress(path));
}

bool RpcSession::setupVsockClient(unsigned int cid, unsigned int port) {
    return setupSocketClient(VsockSocketAddress(cid, port));
}

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

    return addClientConnection(std::move(serverFd));
}

sp<IBinder> RpcSession::getRootObject() {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return nullptr;
    return state()->getRootObject(connection.fd(), sp<RpcSession>::fromExisting(this));
}

status_t RpcSession::getRemoteMaxThreads(size_t* maxThreads) {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return status;
    return state()->getMaxThreads(connection.fd(), sp<RpcSession>::fromExisting(this), maxThreads);
}

bool RpcSession::shutdownAndWait(bool wait) {
    std::unique_lock<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(mShutdownTrigger == nullptr, "Shutdown trigger not installed");

    mShutdownTrigger->trigger();

    if (wait) {
        LOG_ALWAYS_FATAL_IF(mShutdownListener == nullptr, "Shutdown listener not installed");
        mShutdownListener->waitForShutdown(_l);
        LOG_ALWAYS_FATAL_IF(!mThreads.empty(), "Shutdown failed");
    }

    _l.unlock();
    mState->clear();

    return true;
}

status_t RpcSession::transact(const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                              Parcel* reply, uint32_t flags) {
    ExclusiveConnection connection;
    status_t status =
            ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                      (flags & IBinder::FLAG_ONEWAY) ? ConnectionUse::CLIENT_ASYNC
                                                                     : ConnectionUse::CLIENT,
                                      &connection);
    if (status != OK) return status;
    return state()->transact(connection.fd(), binder, code, data,
                             sp<RpcSession>::fromExisting(this), reply, flags);
}

status_t RpcSession::sendDecStrong(const RpcAddress& address) {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT_REFCOUNT, &connection);
    if (status != OK) return status;
    return state()->sendDecStrong(connection.fd(), sp<RpcSession>::fromExisting(this), address);
}

std::unique_ptr<RpcSession::FdTrigger> RpcSession::FdTrigger::make() {
    auto ret = std::make_unique<RpcSession::FdTrigger>();
    if (!android::base::Pipe(&ret->mRead, &ret->mWrite)) {
        ALOGE("Could not create pipe %s", strerror(errno));
        return nullptr;
    }
    return ret;
}

void RpcSession::FdTrigger::trigger() {
    mWrite.reset();
}

bool RpcSession::FdTrigger::isTriggered() {
    return mWrite == -1;
}

status_t RpcSession::FdTrigger::triggerablePollRead(base::borrowed_fd fd) {
    while (true) {
        pollfd pfd[]{{.fd = fd.get(), .events = POLLIN | POLLHUP, .revents = 0},
                     {.fd = mRead.get(), .events = POLLHUP, .revents = 0}};
        int ret = TEMP_FAILURE_RETRY(poll(pfd, arraysize(pfd), -1));
        if (ret < 0) {
            return -errno;
        }
        if (ret == 0) {
            continue;
        }
        if (pfd[1].revents & POLLHUP) {
            return -ECANCELED;
        }
        return pfd[0].revents & POLLIN ? OK : DEAD_OBJECT;
    }
}

status_t RpcSession::FdTrigger::interruptableReadFully(base::borrowed_fd fd, void* data,
                                                       size_t size) {
    uint8_t* buffer = reinterpret_cast<uint8_t*>(data);
    uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    status_t status;
    while ((status = triggerablePollRead(fd)) == OK) {
        ssize_t readSize = TEMP_FAILURE_RETRY(recv(fd.get(), buffer, end - buffer, MSG_NOSIGNAL));
        if (readSize == 0) return DEAD_OBJECT; // EOF

        if (readSize < 0) {
            return -errno;
        }
        buffer += readSize;
        if (buffer == end) return OK;
    }
    return status;
}

status_t RpcSession::readId() {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mForServer != nullptr, "Can only update ID for client.");
    }

    int32_t id;

    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return status;

    status = state()->getSessionId(connection.fd(), sp<RpcSession>::fromExisting(this), &id);
    if (status != OK) return status;

    LOG_RPC_DETAIL("RpcSession %p has id %d", this, id);
    mId = id;
    return OK;
}

void RpcSession::WaitForShutdownListener::onSessionLockedAllServerThreadsEnded(
        const sp<RpcSession>& session) {
    (void)session;
    mShutdown = true;
}

void RpcSession::WaitForShutdownListener::onSessionServerThreadEnded() {
    mCv.notify_all();
}

void RpcSession::WaitForShutdownListener::waitForShutdown(std::unique_lock<std::mutex>& lock) {
    while (!mShutdown) {
        if (std::cv_status::timeout == mCv.wait_for(lock, std::chrono::seconds(1))) {
            ALOGE("Waiting for RpcSession to shut down (1s w/o progress).");
        }
    }
}

void RpcSession::preJoinThreadOwnership(std::thread thread) {
    LOG_ALWAYS_FATAL_IF(thread.get_id() != std::this_thread::get_id(), "Must own this thread");

    {
        std::lock_guard<std::mutex> _l(mMutex);
        mThreads[thread.get_id()] = std::move(thread);
    }
}

RpcSession::PreJoinSetupResult RpcSession::preJoinSetup(base::unique_fd fd) {
    // must be registered to allow arbitrary client code executing commands to
    // be able to do nested calls (we can't only read from it)
    sp<RpcConnection> connection = assignServerToThisThread(std::move(fd));

    status_t status =
            mState->readConnectionInit(connection->fd, sp<RpcSession>::fromExisting(this));

    return PreJoinSetupResult{
            .connection = std::move(connection),
            .status = status,
    };
}

void RpcSession::join(sp<RpcSession>&& session, PreJoinSetupResult&& setupResult) {
    sp<RpcConnection>& connection = setupResult.connection;

    if (setupResult.status == OK) {
        while (true) {
            status_t status = session->state()->getAndExecuteCommand(connection->fd, session,
                                                                     RpcState::CommandType::ANY);
            if (status != OK) {
                LOG_RPC_DETAIL("Binder connection thread closing w/ status %s",
                               statusToString(status).c_str());
                break;
            }
        }
    } else {
        ALOGE("Connection failed to init, closing with status %s",
              statusToString(setupResult.status).c_str());
    }

    LOG_ALWAYS_FATAL_IF(!session->removeServerConnection(connection),
                        "bad state: connection object guaranteed to be in list");

    sp<RpcSession::EventListener> listener;
    {
        std::lock_guard<std::mutex> _l(session->mMutex);
        auto it = session->mThreads.find(std::this_thread::get_id());
        LOG_ALWAYS_FATAL_IF(it == session->mThreads.end());
        it->second.detach();
        session->mThreads.erase(it);

        listener = session->mEventListener.promote();
    }

    session = nullptr;

    if (listener != nullptr) {
        listener->onSessionServerThreadEnded();
    }
}

wp<RpcServer> RpcSession::server() {
    return mForServer;
}

bool RpcSession::setupSocketClient(const RpcSocketAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mClientConnections.size() != 0,
                            "Must only setup session once, but already has %zu clients",
                            mClientConnections.size());
    }

    if (!setupOneSocketConnection(addr, RPC_SESSION_ID_NEW, false /*reverse*/)) return false;

    // TODO(b/189955605): we should add additional sessions dynamically
    // instead of all at once.
    // TODO(b/186470974): first risk of blocking
    size_t numThreadsAvailable;
    if (status_t status = getRemoteMaxThreads(&numThreadsAvailable); status != OK) {
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
        // TODO(b/189955605): shutdown existing connections?
        if (!setupOneSocketConnection(addr, mId.value(), false /*reverse*/)) return false;
    }

    // TODO(b/189955605): we should add additional sessions dynamically
    // instead of all at once - the other side should be responsible for setting
    // up additional connections. We need to create at least one (unless 0 are
    // requested to be set) in order to allow the other side to reliably make
    // any requests at all.

    for (size_t i = 0; i < mMaxThreads; i++) {
        if (!setupOneSocketConnection(addr, mId.value(), true /*reverse*/)) return false;
    }

    return true;
}

bool RpcSession::setupOneSocketConnection(const RpcSocketAddress& addr, int32_t id, bool reverse) {
    for (size_t tries = 0; tries < 5; tries++) {
        if (tries > 0) usleep(10000);

        unique_fd serverFd(
                TEMP_FAILURE_RETRY(socket(addr.addr()->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0)));
        if (serverFd == -1) {
            int savedErrno = errno;
            ALOGE("Could not create socket at %s: %s", addr.toString().c_str(),
                  strerror(savedErrno));
            return false;
        }

        if (0 != TEMP_FAILURE_RETRY(connect(serverFd.get(), addr.addr(), addr.addrSize()))) {
            if (errno == ECONNRESET) {
                ALOGW("Connection reset on %s", addr.toString().c_str());
                continue;
            }
            int savedErrno = errno;
            ALOGE("Could not connect socket at %s: %s", addr.toString().c_str(),
                  strerror(savedErrno));
            return false;
        }

        RpcConnectionHeader header{
                .sessionId = id,
        };
        if (reverse) header.options |= RPC_CONNECTION_OPTION_REVERSE;

        if (sizeof(header) != TEMP_FAILURE_RETRY(write(serverFd.get(), &header, sizeof(header)))) {
            int savedErrno = errno;
            ALOGE("Could not write connection header to socket at %s: %s", addr.toString().c_str(),
                  strerror(savedErrno));
            return false;
        }

        LOG_RPC_DETAIL("Socket at %s client with fd %d", addr.toString().c_str(), serverFd.get());

        if (reverse) {
            std::mutex mutex;
            std::condition_variable joinCv;
            std::unique_lock<std::mutex> lock(mutex);
            std::thread thread;
            sp<RpcSession> thiz = sp<RpcSession>::fromExisting(this);
            bool ownershipTransferred = false;
            thread = std::thread([&]() {
                std::unique_lock<std::mutex> threadLock(mutex);
                unique_fd fd = std::move(serverFd);
                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
                sp<RpcSession> session = thiz;
                session->preJoinThreadOwnership(std::move(thread));

                // only continue once we have a response or the connection fails
                auto setupResult = session->preJoinSetup(std::move(fd));

                ownershipTransferred = true;
                threadLock.unlock();
                joinCv.notify_one();
                // do not use & vars below

                RpcSession::join(std::move(session), std::move(setupResult));
            });
            joinCv.wait(lock, [&] { return ownershipTransferred; });
            LOG_ALWAYS_FATAL_IF(!ownershipTransferred);
            return true;
        } else {
            return addClientConnection(std::move(serverFd));
        }
    }

    ALOGE("Ran out of retries to connect to %s", addr.toString().c_str());
    return false;
}

bool RpcSession::addClientConnection(unique_fd fd) {
    sp<RpcConnection> connection = sp<RpcConnection>::make();
    {
        std::lock_guard<std::mutex> _l(mMutex);

        // first client connection added, but setForServer not called, so
        // initializaing for a client.
        if (mShutdownTrigger == nullptr) {
            mShutdownTrigger = FdTrigger::make();
            mEventListener = mShutdownListener = sp<WaitForShutdownListener>::make();
            if (mShutdownTrigger == nullptr) return false;
        }

        connection->fd = std::move(fd);
        connection->exclusiveTid = gettid();
        mClientConnections.push_back(connection);
    }

    status_t status =
            mState->sendConnectionInit(connection->fd, sp<RpcSession>::fromExisting(this));

    {
        std::lock_guard<std::mutex> _l(mMutex);
        connection->exclusiveTid = std::nullopt;
    }

    return status == OK;
}

bool RpcSession::setForServer(const wp<RpcServer>& server, const wp<EventListener>& eventListener,
                              int32_t sessionId) {
    LOG_ALWAYS_FATAL_IF(mForServer != nullptr);
    LOG_ALWAYS_FATAL_IF(server == nullptr);
    LOG_ALWAYS_FATAL_IF(mEventListener != nullptr);
    LOG_ALWAYS_FATAL_IF(eventListener == nullptr);
    LOG_ALWAYS_FATAL_IF(mShutdownTrigger != nullptr);

    mShutdownTrigger = FdTrigger::make();
    if (mShutdownTrigger == nullptr) return false;

    mId = sessionId;
    mForServer = server;
    mEventListener = eventListener;
    return true;
}

sp<RpcSession::RpcConnection> RpcSession::assignServerToThisThread(unique_fd fd) {
    std::lock_guard<std::mutex> _l(mMutex);
    sp<RpcConnection> session = sp<RpcConnection>::make();
    session->fd = std::move(fd);
    session->exclusiveTid = gettid();
    mServerConnections.push_back(session);

    return session;
}

bool RpcSession::removeServerConnection(const sp<RpcConnection>& connection) {
    std::lock_guard<std::mutex> _l(mMutex);
    if (auto it = std::find(mServerConnections.begin(), mServerConnections.end(), connection);
        it != mServerConnections.end()) {
        mServerConnections.erase(it);
        if (mServerConnections.size() == 0) {
            sp<EventListener> listener = mEventListener.promote();
            if (listener) {
                listener->onSessionLockedAllServerThreadsEnded(sp<RpcSession>::fromExisting(this));
            }
        }
        return true;
    }
    return false;
}

status_t RpcSession::ExclusiveConnection::find(const sp<RpcSession>& session, ConnectionUse use,
                                               ExclusiveConnection* connection) {
    connection->mSession = session;
    connection->mConnection = nullptr;
    connection->mReentrant = false;

    pid_t tid = gettid();
    std::unique_lock<std::mutex> _l(session->mMutex);

    session->mWaitingThreads++;
    while (true) {
        sp<RpcConnection> exclusive;
        sp<RpcConnection> available;

        // CHECK FOR DEDICATED CLIENT SOCKET
        //
        // A server/looper should always use a dedicated connection if available
        findConnection(tid, &exclusive, &available, session->mClientConnections,
                       session->mClientConnectionsOffset);

        // WARNING: this assumes a server cannot request its client to send
        // a transaction, as mServerConnections is excluded below.
        //
        // Imagine we have more than one thread in play, and a single thread
        // sends a synchronous, then an asynchronous command. Imagine the
        // asynchronous command is sent on the first client connection. Then, if
        // we naively send a synchronous command to that same connection, the
        // thread on the far side might be busy processing the asynchronous
        // command. So, we move to considering the second available thread
        // for subsequent calls.
        if (use == ConnectionUse::CLIENT_ASYNC && (exclusive != nullptr || available != nullptr)) {
            session->mClientConnectionsOffset =
                    (session->mClientConnectionsOffset + 1) % session->mClientConnections.size();
        }

        // USE SERVING SOCKET (for nested transaction)
        //
        // asynchronous calls cannot be nested
        if (use != ConnectionUse::CLIENT_ASYNC) {
            // server connections are always assigned to a thread
            findConnection(tid, &exclusive, nullptr /*available*/, session->mServerConnections,
                           0 /* index hint */);
        }

        // if our thread is already using a connection, prioritize using that
        if (exclusive != nullptr) {
            connection->mConnection = exclusive;
            connection->mReentrant = true;
            break;
        } else if (available != nullptr) {
            connection->mConnection = available;
            connection->mConnection->exclusiveTid = tid;
            break;
        }

        if (session->mClientConnections.size() == 0) {
            ALOGE("Session has no client connections. This is required for an RPC server to make "
                  "any non-nested (e.g. oneway or on another thread) calls. Use: %d. Server "
                  "connections: %zu",
                  static_cast<int>(use), session->mServerConnections.size());
            return WOULD_BLOCK;
        }

        LOG_RPC_DETAIL("No available connections (have %zu clients and %zu servers). Waiting...",
                       session->mClientConnections.size(), session->mServerConnections.size());
        session->mAvailableConnectionCv.wait(_l);
    }
    session->mWaitingThreads--;

    return OK;
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

RpcSession::ExclusiveConnection::~ExclusiveConnection() {
    // reentrant use of a connection means something less deep in the call stack
    // is using this fd, and it retains the right to it. So, we don't give up
    // exclusive ownership, and no thread is freed.
    if (!mReentrant && mConnection != nullptr) {
        std::unique_lock<std::mutex> _l(mSession->mMutex);
        mConnection->exclusiveTid = std::nullopt;
        if (mSession->mWaitingThreads > 0) {
            _l.unlock();
            mSession->mAvailableConnectionCv.notify_one();
        }
    }
}

} // namespace android
