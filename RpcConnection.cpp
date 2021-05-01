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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <string_view>

#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <utils/String8.h>

#include "RpcState.h"
#include "RpcWireFormat.h"

#ifdef __GLIBC__
extern "C" pid_t gettid();
#endif

#ifdef __BIONIC__
#include <linux/vm_sockets.h>
#endif

namespace android {

using base::borrowed_fd;
using base::unique_fd;
using AddrInfo = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>;

namespace {
bool checkSockaddrSize(const char* name, size_t actual, size_t expected) {
    if (actual >= expected) return true;
    ALOGW("getSockaddrPort: family is %s but size is %zu < %zu", name, actual, expected);
    return false;
}

// Get the port number of |storage| for certain families. Requires storage->sa_family to be
// set to a known family; otherwise, return nullopt.
std::optional<unsigned int> getSockaddrPort(const sockaddr* storage, socklen_t len) {
    switch (storage->sa_family) {
        case AF_INET: {
            if (!checkSockaddrSize("INET", len, sizeof(sockaddr_in))) return std::nullopt;
            auto inetStorage = reinterpret_cast<const sockaddr_in*>(storage);
            return ntohs(inetStorage->sin_port);
        }
        default: {
            uint16_t family = storage->sa_family;
            ALOGW("Don't know how to infer port for family %" PRIu16, family);
            return std::nullopt;
        }
    }
}

std::optional<unsigned int> getSocketPort(borrowed_fd socketfd,
                                          const RpcConnection::SocketAddress& socketAddress) {
    sockaddr_storage storage{};
    socklen_t len = sizeof(storage);
    auto storagePtr = reinterpret_cast<sockaddr*>(&storage);
    if (0 != getsockname(socketfd.get(), storagePtr, &len)) {
        int savedErrno = errno;
        ALOGE("Could not getsockname at %s: %s", socketAddress.toString().c_str(),
              strerror(savedErrno));
        return std::nullopt;
    }

    // getsockname does not fill in family, but getSockaddrPort() needs it.
    if (storage.ss_family == AF_UNSPEC) {
        storage.ss_family = socketAddress.addr()->sa_family;
    }
    return getSockaddrPort(storagePtr, len);
}

} // namespace

RpcConnection::SocketAddress::~SocketAddress() {}

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

class UnixSocketAddress : public RpcConnection::SocketAddress {
public:
    explicit UnixSocketAddress(const char* path) : mAddr({.sun_family = AF_UNIX}) {
        unsigned int pathLen = strlen(path) + 1;
        LOG_ALWAYS_FATAL_IF(pathLen > sizeof(mAddr.sun_path), "Socket path is too long: %u %s",
                            pathLen, path);
        memcpy(mAddr.sun_path, path, pathLen);
    }
    virtual ~UnixSocketAddress() {}
    std::string toString() const override {
        return String8::format("path '%.*s'", static_cast<int>(sizeof(mAddr.sun_path)),
                               mAddr.sun_path)
                .c_str();
    }
    const sockaddr* addr() const override { return reinterpret_cast<const sockaddr*>(&mAddr); }
    size_t addrSize() const override { return sizeof(mAddr); }

private:
    sockaddr_un mAddr;
};

bool RpcConnection::setupUnixDomainServer(const char* path) {
    return setupSocketServer(UnixSocketAddress(path));
}

bool RpcConnection::setupUnixDomainClient(const char* path) {
    return setupSocketClient(UnixSocketAddress(path));
}

#ifdef __BIONIC__

class VsockSocketAddress : public RpcConnection::SocketAddress {
public:
    VsockSocketAddress(unsigned int cid, unsigned int port)
          : mAddr({
                    .svm_family = AF_VSOCK,
                    .svm_port = port,
                    .svm_cid = cid,
            }) {}
    virtual ~VsockSocketAddress() {}
    std::string toString() const override {
        return String8::format("cid %u port %u", mAddr.svm_cid, mAddr.svm_port).c_str();
    }
    const sockaddr* addr() const override { return reinterpret_cast<const sockaddr*>(&mAddr); }
    size_t addrSize() const override { return sizeof(mAddr); }

private:
    sockaddr_vm mAddr;
};

bool RpcConnection::setupVsockServer(unsigned int port) {
    // realizing value w/ this type at compile time to avoid ubsan abort
    constexpr unsigned int kAnyCid = VMADDR_CID_ANY;

    return setupSocketServer(VsockSocketAddress(kAnyCid, port));
}

bool RpcConnection::setupVsockClient(unsigned int cid, unsigned int port) {
    return setupSocketClient(VsockSocketAddress(cid, port));
}

#endif // __BIONIC__

class InetSocketAddress : public RpcConnection::SocketAddress {
public:
    InetSocketAddress(const sockaddr* sockAddr, size_t size, const char* addr, unsigned int port)
          : mSockAddr(sockAddr), mSize(size), mAddr(addr), mPort(port) {}
    [[nodiscard]] std::string toString() const override {
        return String8::format("%s:%u", mAddr, mPort).c_str();
    }
    [[nodiscard]] const sockaddr* addr() const override { return mSockAddr; }
    [[nodiscard]] size_t addrSize() const override { return mSize; }

private:
    const sockaddr* mSockAddr;
    size_t mSize;
    const char* mAddr;
    unsigned int mPort;
};

AddrInfo GetAddrInfo(const char* addr, unsigned int port) {
    addrinfo hint{
            .ai_flags = 0,
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = 0,
    };
    addrinfo* aiStart = nullptr;
    if (int rc = getaddrinfo(addr, std::to_string(port).data(), &hint, &aiStart); 0 != rc) {
        ALOGE("Unable to resolve %s:%u: %s", addr, port, gai_strerror(rc));
        return AddrInfo(nullptr, nullptr);
    }
    if (aiStart == nullptr) {
        ALOGE("Unable to resolve %s:%u: getaddrinfo returns null", addr, port);
        return AddrInfo(nullptr, nullptr);
    }
    return AddrInfo(aiStart, &freeaddrinfo);
}

bool RpcConnection::setupInetServer(unsigned int port, unsigned int* assignedPort) {
    const char* kAddr = "127.0.0.1";

    if (assignedPort != nullptr) *assignedPort = 0;
    auto aiStart = GetAddrInfo(kAddr, port);
    if (aiStart == nullptr) return false;
    for (auto ai = aiStart.get(); ai != nullptr; ai = ai->ai_next) {
        InetSocketAddress socketAddress(ai->ai_addr, ai->ai_addrlen, kAddr, port);
        if (!setupSocketServer(socketAddress)) {
            continue;
        }
        auto realPort = getSocketPort(mServer.get(), socketAddress);
        LOG_ALWAYS_FATAL_IF(!realPort.has_value(), "Unable to get port number after setting up %s",
                            socketAddress.toString().c_str());
        LOG_ALWAYS_FATAL_IF(port != 0 && *realPort != port,
                            "Requesting inet server on %s but it is set up on %u.",
                            socketAddress.toString().c_str(), *realPort);
        if (assignedPort != nullptr) {
            *assignedPort = *realPort;
        }
        return true;
    }
    ALOGE("None of the socket address resolved for %s:%u can be set up as inet server.", kAddr,
          port);
    return false;
}

bool RpcConnection::setupInetClient(const char* addr, unsigned int port) {
    auto aiStart = GetAddrInfo(addr, port);
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

void RpcConnection::join() {
    // TODO(b/185167543): do this dynamically, instead of from a static number
    // of threads
    unique_fd clientFd(
            TEMP_FAILURE_RETRY(accept4(mServer.get(), nullptr, 0 /*length*/, SOCK_CLOEXEC)));
    if (clientFd < 0) {
        // If this log becomes confusing, should save more state from setupUnixDomainServer
        // in order to output here.
        ALOGE("Could not accept4 socket: %s", strerror(errno));
        return;
    }

    LOG_RPC_DETAIL("accept4 on fd %d yields fd %d", mServer.get(), clientFd.get());

    // must be registered to allow arbitrary client code executing commands to
    // be able to do nested calls (we can't only read from it)
    sp<ConnectionSocket> socket = assignServerToThisThread(std::move(clientFd));

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

void RpcConnection::setForServer(const wp<RpcServer>& server) {
    mForServer = server;
}

wp<RpcServer> RpcConnection::server() {
    return mForServer;
}

bool RpcConnection::setupSocketServer(const SocketAddress& addr) {
    LOG_ALWAYS_FATAL_IF(mServer.get() != -1, "Each RpcConnection can only have one server.");

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

    mServer = std::move(serverFd);
    return true;
}

bool RpcConnection::setupSocketClient(const SocketAddress& addr) {
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

bool RpcConnection::setupOneSocketClient(const SocketAddress& addr) {
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
