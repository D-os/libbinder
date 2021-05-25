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

#include <sys/socket.h>
#include <sys/un.h>

#include <thread>
#include <vector>

#include <android-base/scopeguard.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <log/log.h>

#include "RpcSocketAddress.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

namespace android {

using base::ScopeGuard;
using base::unique_fd;

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {
    (void)shutdown();
}

sp<RpcServer> RpcServer::make() {
    return sp<RpcServer>::make();
}

void RpcServer::iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction() {
    mAgreedExperimental = true;
}

bool RpcServer::setupUnixDomainServer(const char* path) {
    return setupSocketServer(UnixSocketAddress(path));
}

bool RpcServer::setupVsockServer(unsigned int port) {
    // realizing value w/ this type at compile time to avoid ubsan abort
    constexpr unsigned int kAnyCid = VMADDR_CID_ANY;

    return setupSocketServer(VsockSocketAddress(kAnyCid, port));
}

bool RpcServer::setupInetServer(unsigned int port, unsigned int* assignedPort) {
    const char* kAddr = "127.0.0.1";

    if (assignedPort != nullptr) *assignedPort = 0;
    auto aiStart = InetSocketAddress::getAddrInfo(kAddr, port);
    if (aiStart == nullptr) return false;
    for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
        InetSocketAddress socketAddress(ai->ai_addr, ai->ai_addrlen, kAddr, port);
        if (!setupSocketServer(socketAddress)) {
            continue;
        }

        LOG_ALWAYS_FATAL_IF(socketAddress.addr()->sa_family != AF_INET, "expecting inet");
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        if (0 != getsockname(mServer.get(), reinterpret_cast<sockaddr*>(&addr), &len)) {
            int savedErrno = errno;
            ALOGE("Could not getsockname at %s: %s", socketAddress.toString().c_str(),
                  strerror(savedErrno));
            return false;
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

        return true;
    }
    ALOGE("None of the socket address resolved for %s:%u can be set up as inet server.", kAddr,
          port);
    return false;
}

void RpcServer::setMaxThreads(size_t threads) {
    LOG_ALWAYS_FATAL_IF(threads <= 0, "RpcServer is useless without threads");
    LOG_ALWAYS_FATAL_IF(mJoinThreadRunning, "Cannot set max threads while running");
    mMaxThreads = threads;
}

size_t RpcServer::getMaxThreads() {
    return mMaxThreads;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObjectWeak = mRootObject = binder;
}

void RpcServer::setRootObjectWeak(const wp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObject.clear();
    mRootObjectWeak = binder;
}

sp<IBinder> RpcServer::getRootObject() {
    std::lock_guard<std::mutex> _l(mLock);
    bool hasWeak = mRootObjectWeak.unsafe_get();
    sp<IBinder> ret = mRootObjectWeak.promote();
    ALOGW_IF(hasWeak && ret == nullptr, "RpcServer root object is freed, returning nullptr");
    return ret;
}

static void joinRpcServer(sp<RpcServer>&& thiz) {
    thiz->join();
}

void RpcServer::start() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    std::lock_guard<std::mutex> _l(mLock);
    LOG_ALWAYS_FATAL_IF(mJoinThread.get(), "Already started!");
    mJoinThread = std::make_unique<std::thread>(&joinRpcServer, sp<RpcServer>::fromExisting(this));
}

void RpcServer::join() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");

    {
        std::lock_guard<std::mutex> _l(mLock);
        LOG_ALWAYS_FATAL_IF(!mServer.ok(), "RpcServer must be setup to join.");
        LOG_ALWAYS_FATAL_IF(mShutdownTrigger != nullptr, "Already joined");
        mJoinThreadRunning = true;
        mShutdownTrigger = RpcSession::FdTrigger::make();
        LOG_ALWAYS_FATAL_IF(mShutdownTrigger == nullptr, "Cannot create join signaler");
    }

    status_t status;
    while ((status = mShutdownTrigger->triggerablePollRead(mServer)) == OK) {
        (void)acceptOne();
    }
    LOG_RPC_DETAIL("RpcServer::join exiting with %s", statusToString(status).c_str());

    {
        std::lock_guard<std::mutex> _l(mLock);
        mJoinThreadRunning = false;
    }
    mShutdownCv.notify_all();
}

bool RpcServer::acceptOne() {
    unique_fd clientFd(
            TEMP_FAILURE_RETRY(accept4(mServer.get(), nullptr, nullptr /*length*/, SOCK_CLOEXEC)));

    if (clientFd < 0) {
        ALOGE("Could not accept4 socket: %s", strerror(errno));
        return false;
    }
    LOG_RPC_DETAIL("accept4 on fd %d yields fd %d", mServer.get(), clientFd.get());

    {
        std::lock_guard<std::mutex> _l(mLock);
        std::thread thread = std::thread(&RpcServer::establishConnection,
                                         sp<RpcServer>::fromExisting(this), std::move(clientFd));
        mConnectingThreads[thread.get_id()] = std::move(thread);
    }

    return true;
}

bool RpcServer::shutdown() {
    std::unique_lock<std::mutex> _l(mLock);
    if (mShutdownTrigger == nullptr) {
        LOG_RPC_DETAIL("Cannot shutdown. No shutdown trigger installed.");
        return false;
    }

    mShutdownTrigger->trigger();
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

void RpcServer::establishConnection(sp<RpcServer>&& server, base::unique_fd clientFd) {
    // TODO(b/183988761): cannot trust this simple ID
    LOG_ALWAYS_FATAL_IF(!server->mAgreedExperimental, "no!");

    // mShutdownTrigger can only be cleared once connection threads have joined.
    // It must be set before this thread is started
    LOG_ALWAYS_FATAL_IF(server->mShutdownTrigger == nullptr);

    int32_t id;
    status_t status =
            server->mShutdownTrigger->interruptableReadFully(clientFd.get(), &id, sizeof(id));
    bool idValid = status == OK;
    if (!idValid) {
        ALOGE("Failed to read ID for client connecting to RPC server: %s",
              statusToString(status).c_str());
        // still need to cleanup before we can return
    }

    std::thread thisThread;
    sp<RpcSession> session;
    {
        std::unique_lock<std::mutex> _l(server->mLock);

        auto threadId = server->mConnectingThreads.find(std::this_thread::get_id());
        LOG_ALWAYS_FATAL_IF(threadId == server->mConnectingThreads.end(),
                            "Must establish connection on owned thread");
        thisThread = std::move(threadId->second);
        ScopeGuard detachGuard = [&]() { thisThread.detach(); };
        server->mConnectingThreads.erase(threadId);

        // TODO(b/185167543): we currently can't disable this because we don't
        // shutdown sessions as well, only the server itself. So, we need to
        // keep this separate from the detachGuard, since we temporarily want to
        // give a notification even when we pass ownership of the thread to
        // a session.
        ScopeGuard threadLifetimeGuard = [&]() {
            _l.unlock();
            server->mShutdownCv.notify_all();
        };

        if (!idValid) {
            return;
        }

        if (id == RPC_SESSION_ID_NEW) {
            LOG_ALWAYS_FATAL_IF(server->mSessionIdCounter >= INT32_MAX, "Out of session IDs");
            server->mSessionIdCounter++;

            session = RpcSession::make();
            session->setForServer(wp<RpcServer>(server), server->mSessionIdCounter,
                                  server->mShutdownTrigger);

            server->mSessions[server->mSessionIdCounter] = session;
        } else {
            auto it = server->mSessions.find(id);
            if (it == server->mSessions.end()) {
                ALOGE("Cannot add thread, no record of session with ID %d", id);
                return;
            }
            session = it->second;
        }

        detachGuard.Disable();
        session->preJoin(std::move(thisThread));
    }

    // avoid strong cycle
    server = nullptr;

    session->join(std::move(clientFd));
}

bool RpcServer::setupSocketServer(const RpcSocketAddress& addr) {
    LOG_RPC_DETAIL("Setting up socket server %s", addr.toString().c_str());
    LOG_ALWAYS_FATAL_IF(hasServer(), "Each RpcServer can only have one server.");

    unique_fd serverFd(
            TEMP_FAILURE_RETRY(socket(addr.addr()->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        ALOGE("Could not create socket: %s", strerror(errno));
        return false;
    }

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd.get(), addr.addr(), addr.addrSize()))) {
        int savedErrno = errno;
        ALOGE("Could not bind socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return false;
    }

    if (0 != TEMP_FAILURE_RETRY(listen(serverFd.get(), 1 /*backlog*/))) {
        int savedErrno = errno;
        ALOGE("Could not listen socket at %s: %s", addr.toString().c_str(), strerror(savedErrno));
        return false;
    }

    LOG_RPC_DETAIL("Successfully setup socket server %s", addr.toString().c_str());

    if (!setupExternalServer(std::move(serverFd))) {
        ALOGE("Another thread has set up server while calling setupSocketServer. Race?");
        return false;
    }
    return true;
}

void RpcServer::onSessionTerminating(const sp<RpcSession>& session) {
    auto id = session->mId;
    LOG_ALWAYS_FATAL_IF(id == std::nullopt, "Server sessions must be initialized with ID");
    LOG_RPC_DETAIL("Dropping session %d", *id);

    std::lock_guard<std::mutex> _l(mLock);
    auto it = mSessions.find(*id);
    LOG_ALWAYS_FATAL_IF(it == mSessions.end(), "Bad state, unknown session id %d", *id);
    LOG_ALWAYS_FATAL_IF(it->second != session, "Bad state, session has id mismatch %d", *id);
    (void)mSessions.erase(it);
}

void RpcServer::onSessionThreadEnding(const sp<RpcSession>& session) {
    (void)session;
    mShutdownCv.notify_all();
}

bool RpcServer::hasServer() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    std::lock_guard<std::mutex> _l(mLock);
    return mServer.ok();
}

unique_fd RpcServer::releaseServer() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    std::lock_guard<std::mutex> _l(mLock);
    return std::move(mServer);
}

bool RpcServer::setupExternalServer(base::unique_fd serverFd) {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    std::lock_guard<std::mutex> _l(mLock);
    if (mServer.ok()) {
        ALOGE("Each RpcServer can only have one server.");
        return false;
    }
    mServer = std::move(serverFd);
    return true;
}

} // namespace android
