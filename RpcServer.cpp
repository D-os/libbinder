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
#include "RpcState.h"

#include "RpcSocketAddress.h"
#include "RpcWireFormat.h"

namespace android {

using base::ScopeGuard;
using base::unique_fd;

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {}

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
    LOG_ALWAYS_FATAL_IF(mStarted, "must be called before started");
    mMaxThreads = threads;
}

size_t RpcServer::getMaxThreads() {
    return mMaxThreads;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    std::lock_guard<std::mutex> _l(mLock);
    mRootObject = binder;
}

sp<IBinder> RpcServer::getRootObject() {
    std::lock_guard<std::mutex> _l(mLock);
    return mRootObject;
}

void RpcServer::join() {
    while (true) {
        (void)acceptOne();
    }
}

bool RpcServer::acceptOne() {
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    LOG_ALWAYS_FATAL_IF(mServer.get() == -1, "RpcServer must be setup to join.");

    unique_fd clientFd(
            TEMP_FAILURE_RETRY(accept4(mServer.get(), nullptr, nullptr /*length*/, SOCK_CLOEXEC)));

    if (clientFd < 0) {
        ALOGE("Could not accept4 socket: %s", strerror(errno));
        return false;
    }
    LOG_RPC_DETAIL("accept4 on fd %d yields fd %d", mServer.get(), clientFd.get());

    {
        std::lock_guard<std::mutex> _l(mLock);
        std::thread thread =
                std::thread(&RpcServer::establishConnection, this,
                            std::move(sp<RpcServer>::fromExisting(this)), std::move(clientFd));
        mConnectingThreads[thread.get_id()] = std::move(thread);
    }

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
    LOG_ALWAYS_FATAL_IF(this != server.get(), "Must pass same ownership object");

    // TODO(b/183988761): cannot trust this simple ID
    LOG_ALWAYS_FATAL_IF(!mAgreedExperimental, "no!");
    bool idValid = true;
    int32_t id;
    if (sizeof(id) != read(clientFd.get(), &id, sizeof(id))) {
        ALOGE("Could not read ID from fd %d", clientFd.get());
        idValid = false;
    }

    std::thread thisThread;
    sp<RpcSession> session;
    {
        std::lock_guard<std::mutex> _l(mLock);

        auto threadId = mConnectingThreads.find(std::this_thread::get_id());
        LOG_ALWAYS_FATAL_IF(threadId == mConnectingThreads.end(),
                            "Must establish connection on owned thread");
        thisThread = std::move(threadId->second);
        ScopeGuard detachGuard = [&]() { thisThread.detach(); };
        mConnectingThreads.erase(threadId);

        if (!idValid) {
            return;
        }

        if (id == RPC_SESSION_ID_NEW) {
            LOG_ALWAYS_FATAL_IF(mSessionIdCounter >= INT32_MAX, "Out of session IDs");
            mSessionIdCounter++;

            session = RpcSession::make();
            session->setForServer(wp<RpcServer>::fromExisting(this), mSessionIdCounter);

            mSessions[mSessionIdCounter] = session;
        } else {
            auto it = mSessions.find(id);
            if (it == mSessions.end()) {
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
    //
    //
    // DO NOT ACCESS MEMBER VARIABLES BELOW
    //

    session->join(std::move(clientFd));
}

bool RpcServer::setupSocketServer(const RpcSocketAddress& addr) {
    LOG_RPC_DETAIL("Setting up socket server %s", addr.toString().c_str());

    {
        std::lock_guard<std::mutex> _l(mLock);
        LOG_ALWAYS_FATAL_IF(mServer.get() != -1, "Each RpcServer can only have one server.");
    }

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

    mServer = std::move(serverFd);
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

} // namespace android
