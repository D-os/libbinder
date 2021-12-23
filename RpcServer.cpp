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

#define LOG_TAG "RpcServer"

#include <inttypes.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/hex.h>
#include <android-base/scopeguard.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcTransportRaw.h>
#include <log/log.h>

#include "FdTrigger.h"
#include "RpcSocketAddress.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

namespace android {

constexpr size_t kSessionIdBytes = 32;

using base::ScopeGuard;
using base::unique_fd;

RpcServer::RpcServer(std::unique_ptr<RpcTransportCtx> ctx) : mCtx(std::move(ctx)) {}
RpcServer::~RpcServer() {
    (void)shutdown();
}

sp<RpcServer> RpcServer::make(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryRaw::make();
    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) return nullptr;
    return sp<RpcServer>::make(std::move(ctx));
}

status_t RpcServer::setupUnixDomainServer(const char* path) {
    return setupSocketServer(UnixSocketAddress(path));
}

status_t RpcServer::setupVsockServer(unsigned int port) {
    // realizing value w/ this type at compile time to avoid ubsan abort
    constexpr unsigned int kAnyCid = VMADDR_CID_ANY;

    return setupSocketServer(VsockSocketAddress(kAnyCid, port));
}

status_t RpcServer::setupInetServer(const char* address, unsigned int port,
                                    unsigned int* assignedPort) {
    if (assignedPort != nullptr) *assignedPort = 0;
    auto aiStart = InetSocketAddress::getAddrInfo(address, port);
    if (aiStart == nullptr) return UNKNOWN_ERROR;
    for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
        InetSocketAddress socketAddress(ai->ai_addr, ai->ai_addrlen, address, port);
        if (status_t status = setupSocketServer(socketAddress); status != OK) {
            continue;
        }

        LOG_ALWAYS_FATAL_IF(socketAddress.addr()->sa_family != AF_INET, "expecting inet");
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        if (0 != getsockname(mServer.get(), reinterpret_cast<sockaddr*>(&addr), &len)) {
            int savedErrno = errno;
            ALOGE("Could not getsockname at %s: %s", socketAddress.toString().c_str(),
                  strerror(savedErrno));
            return -savedErrno;
        }
        LOG_ALWAYS_FATAL_IF(len != sizeof(addr), "Wrong socket type: len %zu vs len %zu",
                            static_cast<size_t>(len), sizeof(addr));
        unsigned int realPort = ntohs(addr.sin_port);
        LOG_ALWAYS_FATAL_IF(port != 0 && realPort != port,
                            "Requesting inet server on %s but it is set up on %u.",
                            socketAddress.toString().c_str(), realPort);

        if (assignedPort != nullptr) {
            *assignedPort = realPort;
        }

        return OK;
    }
    ALOGE("None of the socket address resolved for %s:%u can be set up as inet server.", address,
          port);
    return UNKNOWN_ERROR;
}

void RpcServer::setMaxThreads(size_t threads) {
    LOG_ALWAYS_FATAL_IF(threads <= 0, "RpcServer is useless without threads");
    LOG_ALWAYS_FATAL_IF(mJoinThreadRunning, "Cannot set max threads while running");
    mMaxThreads = threads;
}

size_t RpcServer::getMaxThreads() {
    return mMaxThreads;
}

void RpcServer::setProtocolVersion(uint32_t version) {
    mProtocolVersion = version;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObjectFactory = nullptr;
    mRootObjectWeak = mRootObject = binder;
}

void RpcServer::setRootObjectWeak(const wp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObject.clear();
    mRootObjectFactory = nullptr;
    mRootObjectWeak = binder;
}
void RpcServer::setPerSessionRootObject(
        std::function<sp<IBinder>(const sockaddr*, socklen_t)>&& makeObject) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObject.clear();
    mRootObjectWeak.clear();
    mRootObjectFactory = std::move(makeObject);
}

sp<IBinder> RpcServer::getRootObject() {
    std::lock_guard<std::mutex> _l(mLock);
    bool hasWeak = mRootObjectWeak.unsafe_get();
    sp<IBinder> ret = mRootObjectWeak.promote();
    ALOGW_IF(hasWeak && ret == nullptr, "RpcServer root object is freed, returning nullptr");
    return ret;
}

std::vector<uint8_t> RpcServer::getCertificate(RpcCertificateFormat format) {
    std::lock_guard<std::mutex> _l(mLock);
    return mCtx->getCertificate(format);
}

static void joinRpcServer(sp<RpcServer>&& thiz) {
    thiz->join();
}

void RpcServer::start() {
    std::lock_guard<std::mutex> _l(mLock);
    LOG_ALWAYS_FATAL_IF(mJoinThread.get(), "Already started!");
    mJoinThread = std::make_unique<std::thread>(&joinRpcServer, sp<RpcServer>::fromExisting(this));
}

void RpcServer::join() {

    {
        std::lock_guard<std::mutex> _l(mLock);
        LOG_ALWAYS_FATAL_IF(!mServer.ok(), "RpcServer must be setup to join.");
        LOG_ALWAYS_FATAL_IF(mShutdownTrigger != nullptr, "Already joined");
        mJoinThreadRunning = true;
        mShutdownTrigger = FdTrigger::make();
        LOG_ALWAYS_FATAL_IF(mShutdownTrigger == nullptr, "Cannot create join signaler");
    }

    status_t status;
    while ((status = mShutdownTrigger->triggerablePoll(mServer, POLLIN)) == OK) {
        sockaddr_storage addr;
        socklen_t addrLen = sizeof(addr);

        unique_fd clientFd(
                TEMP_FAILURE_RETRY(accept4(mServer.get(), reinterpret_cast<sockaddr*>(&addr),
                                           &addrLen, SOCK_CLOEXEC | SOCK_NONBLOCK)));

        LOG_ALWAYS_FATAL_IF(addrLen > static_cast<socklen_t>(sizeof(addr)), "Truncated address");

        if (clientFd < 0) {
            ALOGE("Could not accept4 socket: %s", strerror(errno));
            continue;
        }
        LOG_RPC_DETAIL("accept4 on fd %d yields fd %d", mServer.get(), clientFd.get());

        {
            std::lock_guard<std::mutex> _l(mLock);
            std::thread thread =
                    std::thread(&RpcServer::establishConnection, sp<RpcServer>::fromExisting(this),
                                std::move(clientFd), addr, addrLen);
            mConnectingThreads[thread.get_id()] = std::move(thread);
        }
    }
    LOG_RPC_DETAIL("RpcServer::join exiting with %s", statusToString(status).c_str());

    {
        std::lock_guard<std::mutex> _l(mLock);
        mJoinThreadRunning = false;
    }
    mShutdownCv.notify_all();
}

bool RpcServer::shutdown() {
    std::unique_lock<std::mutex> _l(mLock);
    if (mShutdownTrigger == nullptr) {
        LOG_RPC_DETAIL("Cannot shutdown. No shutdown trigger installed (already shutdown?)");
        return false;
    }

    mShutdownTrigger->trigger();

    for (auto& [id, session] : mSessions) {
        (void)id;
        // server lock is a more general lock
        std::lock_guard<std::mutex> _lSession(session->mMutex);
        session->mShutdownTrigger->trigger();
    }

    while (mJoinThreadRunning || !mConnectingThreads.empty() || !mSessions.empty()) {
        if (std::cv_status::timeout == mShutdownCv.wait_for(_l, std::chrono::seconds(1))) {
            ALOGE("Waiting for RpcServer to shut down (1s w/o progress). Join thread running: %d, "
                  "Connecting threads: "
                  "%zu, Sessions: %zu. Is your server deadlocked?",
                  mJoinThreadRunning, mConnectingThreads.size(), mSessions.size());
        }
    }

    // At this point, we know join() is about to exit, but the thread that calls
    // join() may not have exited yet.
    // If RpcServer owns the join thread (aka start() is called), make sure the thread exits;
    // otherwise ~thread() may call std::terminate(), which may crash the process.
    // If RpcServer does not own the join thread (aka join() is called directly),
    // then the owner of RpcServer is responsible for cleaning up that thread.
    if (mJoinThread.get()) {
        mJoinThread->join();
        mJoinThread.reset();
    }

    LOG_RPC_DETAIL("Finished waiting on shutdown.");

    mShutdownTrigger = nullptr;
    return true;
}

std::vector<sp<RpcSession>> RpcServer::listSessions() {
    std::lock_guard<std::mutex> _l(mLock);
    std::vector<sp<RpcSession>> sessions;
    for (auto& [id, session] : mSessions) {
        (void)id;
        sessions.push_back(session);
    }
    return sessions;
}

size_t RpcServer::numUninitializedSessions() {
    std::lock_guard<std::mutex> _l(mLock);
    return mConnectingThreads.size();
}

void RpcServer::establishConnection(sp<RpcServer>&& server, base::unique_fd clientFd,
                                    const sockaddr_storage addr, socklen_t addrLen) {
    // mShutdownTrigger can only be cleared once connection threads have joined.
    // It must be set before this thread is started
    LOG_ALWAYS_FATAL_IF(server->mShutdownTrigger == nullptr);
    LOG_ALWAYS_FATAL_IF(server->mCtx == nullptr);

    status_t status = OK;

    int clientFdForLog = clientFd.get();
    auto client = server->mCtx->newTransport(std::move(clientFd), server->mShutdownTrigger.get());
    if (client == nullptr) {
        ALOGE("Dropping accept4()-ed socket because sslAccept fails");
        status = DEAD_OBJECT;
        // still need to cleanup before we can return
    } else {
        LOG_RPC_DETAIL("Created RpcTransport %p for client fd %d", client.get(), clientFdForLog);
    }

    RpcConnectionHeader header;
    if (status == OK) {
        iovec iov{&header, sizeof(header)};
        status = client->interruptableReadFully(server->mShutdownTrigger.get(), &iov, 1, {});
        if (status != OK) {
            ALOGE("Failed to read ID for client connecting to RPC server: %s",
                  statusToString(status).c_str());
            // still need to cleanup before we can return
        }
    }

    std::vector<uint8_t> sessionId;
    if (status == OK) {
        if (header.sessionIdSize > 0) {
            if (header.sessionIdSize == kSessionIdBytes) {
                sessionId.resize(header.sessionIdSize);
                iovec iov{sessionId.data(), sessionId.size()};
                status =
                        client->interruptableReadFully(server->mShutdownTrigger.get(), &iov, 1, {});
                if (status != OK) {
                    ALOGE("Failed to read session ID for client connecting to RPC server: %s",
                          statusToString(status).c_str());
                    // still need to cleanup before we can return
                }
            } else {
                ALOGE("Malformed session ID. Expecting session ID of size %zu but got %" PRIu16,
                      kSessionIdBytes, header.sessionIdSize);
                status = BAD_VALUE;
            }
        }
    }

    bool incoming = false;
    uint32_t protocolVersion = 0;
    bool requestingNewSession = false;

    if (status == OK) {
        incoming = header.options & RPC_CONNECTION_OPTION_INCOMING;
        protocolVersion = std::min(header.version,
                                   server->mProtocolVersion.value_or(RPC_WIRE_PROTOCOL_VERSION));
        requestingNewSession = sessionId.empty();

        if (requestingNewSession) {
            RpcNewSessionResponse response{
                    .version = protocolVersion,
            };

            iovec iov{&response, sizeof(response)};
            status = client->interruptableWriteFully(server->mShutdownTrigger.get(), &iov, 1, {});
            if (status != OK) {
                ALOGE("Failed to send new session response: %s", statusToString(status).c_str());
                // still need to cleanup before we can return
            }
        }
    }

    std::thread thisThread;
    sp<RpcSession> session;
    {
        std::unique_lock<std::mutex> _l(server->mLock);

        auto threadId = server->mConnectingThreads.find(std::this_thread::get_id());
        LOG_ALWAYS_FATAL_IF(threadId == server->mConnectingThreads.end(),
                            "Must establish connection on owned thread");
        thisThread = std::move(threadId->second);
        ScopeGuard detachGuard = [&]() {
            thisThread.detach();
            _l.unlock();
            server->mShutdownCv.notify_all();
        };
        server->mConnectingThreads.erase(threadId);

        if (status != OK || server->mShutdownTrigger->isTriggered()) {
            return;
        }

        if (requestingNewSession) {
            if (incoming) {
                ALOGE("Cannot create a new session with an incoming connection, would leak");
                return;
            }

            // Uniquely identify session at the application layer. Even if a
            // client/server use the same certificates, if they create multiple
            // sessions, we still want to distinguish between them.
            sessionId.resize(kSessionIdBytes);
            size_t tries = 0;
            do {
                // don't block if there is some entropy issue
                if (tries++ > 5) {
                    ALOGE("Cannot find new address: %s",
                          base::HexString(sessionId.data(), sessionId.size()).c_str());
                    return;
                }

                base::unique_fd fd(TEMP_FAILURE_RETRY(
                        open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)));
                if (!base::ReadFully(fd, sessionId.data(), sessionId.size())) {
                    ALOGE("Could not read from /dev/urandom to create session ID");
                    return;
                }
            } while (server->mSessions.end() != server->mSessions.find(sessionId));

            session = RpcSession::make();
            session->setMaxIncomingThreads(server->mMaxThreads);
            if (!session->setProtocolVersion(protocolVersion)) return;

            // if null, falls back to server root
            sp<IBinder> sessionSpecificRoot;
            if (server->mRootObjectFactory != nullptr) {
                sessionSpecificRoot =
                        server->mRootObjectFactory(reinterpret_cast<const sockaddr*>(&addr),
                                                   addrLen);
                if (sessionSpecificRoot == nullptr) {
                    ALOGE("Warning: server returned null from root object factory");
                }
            }

            if (!session->setForServer(server,
                                       sp<RpcServer::EventListener>::fromExisting(
                                               static_cast<RpcServer::EventListener*>(
                                                       server.get())),
                                       sessionId, sessionSpecificRoot)) {
                ALOGE("Failed to attach server to session");
                return;
            }

            server->mSessions[sessionId] = session;
        } else {
            auto it = server->mSessions.find(sessionId);
            if (it == server->mSessions.end()) {
                ALOGE("Cannot add thread, no record of session with ID %s",
                      base::HexString(sessionId.data(), sessionId.size()).c_str());
                return;
            }
            session = it->second;
        }

        if (incoming) {
            LOG_ALWAYS_FATAL_IF(OK != session->addOutgoingConnection(std::move(client), true),
                                "server state must already be initialized");
            return;
        }

        detachGuard.Disable();
        session->preJoinThreadOwnership(std::move(thisThread));
    }

    auto setupResult = session->preJoinSetup(std::move(client));

    // avoid strong cycle
    server = nullptr;

    RpcSession::join(std::move(session), std::move(setupResult));
}

status_t RpcServer::setupSocketServer(const RpcSocketAddress& addr) {
    LOG_RPC_DETAIL("Setting up socket server %s", addr.toString().c_str());
    LOG_ALWAYS_FATAL_IF(hasServer(), "Each RpcServer can only have one server.");

    unique_fd serverFd(TEMP_FAILURE_RETRY(
            socket(addr.addr()->sa_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)));
    if (serverFd == -1) {
        int savedErrno = errno;
        ALOGE("Could not create socket: %s", strerror(savedErrno));
        return -savedErrno;
    }

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd.get(), addr.addr(), addr.addrSize()))) {
        int savedErrno = errno;
        ALOGE("Could not bind socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return -savedErrno;
    }

    // Right now, we create all threads at once, making accept4 slow. To avoid hanging the client,
    // the backlog is increased to a large number.
    // TODO(b/189955605): Once we create threads dynamically & lazily, the backlog can be reduced
    //  to 1.
    if (0 != TEMP_FAILURE_RETRY(listen(serverFd.get(), 50 /*backlog*/))) {
        int savedErrno = errno;
        ALOGE("Could not listen socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return -savedErrno;
    }

    LOG_RPC_DETAIL("Successfully setup socket server %s", addr.toString().c_str());

    if (status_t status = setupExternalServer(std::move(serverFd)); status != OK) {
        ALOGE("Another thread has set up server while calling setupSocketServer. Race?");
        return status;
    }
    return OK;
}

void RpcServer::onSessionAllIncomingThreadsEnded(const sp<RpcSession>& session) {
    const std::vector<uint8_t>& id = session->mId;
    LOG_ALWAYS_FATAL_IF(id.empty(), "Server sessions must be initialized with ID");
    LOG_RPC_DETAIL("Dropping session with address %s",
                   base::HexString(id.data(), id.size()).c_str());

    std::lock_guard<std::mutex> _l(mLock);
    auto it = mSessions.find(id);
    LOG_ALWAYS_FATAL_IF(it == mSessions.end(), "Bad state, unknown session id %s",
                        base::HexString(id.data(), id.size()).c_str());
    LOG_ALWAYS_FATAL_IF(it->second != session, "Bad state, session has id mismatch %s",
                        base::HexString(id.data(), id.size()).c_str());
    (void)mSessions.erase(it);
}

void RpcServer::onSessionIncomingThreadEnded() {
    mShutdownCv.notify_all();
}

bool RpcServer::hasServer() {
    std::lock_guard<std::mutex> _l(mLock);
    return mServer.ok();
}

unique_fd RpcServer::releaseServer() {
    std::lock_guard<std::mutex> _l(mLock);
    return std::move(mServer);
}

status_t RpcServer::setupExternalServer(base::unique_fd serverFd) {
    std::lock_guard<std::mutex> _l(mLock);
    if (mServer.ok()) {
        ALOGE("Each RpcServer can only have one server.");
        return INVALID_OPERATION;
    }
    mServer = std::move(serverFd);
    return OK;
}

} // namespace android
