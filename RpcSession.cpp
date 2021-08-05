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

#include <dlfcn.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include <string_view>

#include <android-base/macros.h>
#include <android_runtime/vm.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcTransportRaw.h>
#include <binder/Stability.h>
#include <jni.h>
#include <utils/String8.h>

#include "RpcSocketAddress.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

#ifdef __GLIBC__
extern "C" pid_t gettid();
#endif

namespace android {

using base::unique_fd;

RpcSession::RpcSession(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory)
      : mRpcTransportCtxFactory(std::move(rpcTransportCtxFactory)) {
    LOG_RPC_DETAIL("RpcSession created %p", this);

    mState = std::make_unique<RpcState>();
}
RpcSession::~RpcSession() {
    LOG_RPC_DETAIL("RpcSession destroyed %p", this);

    std::lock_guard<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(mIncomingConnections.size() != 0,
                        "Should not be able to destroy a session with servers in use.");
}

sp<RpcSession> RpcSession::make(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryRaw::make();
    return sp<RpcSession>::make(std::move(rpcTransportCtxFactory));
}

void RpcSession::setMaxThreads(size_t threads) {
    std::lock_guard<std::mutex> _l(mMutex);
    LOG_ALWAYS_FATAL_IF(!mOutgoingConnections.empty() || !mIncomingConnections.empty(),
                        "Must set max threads before setting up connections, but has %zu client(s) "
                        "and %zu server(s)",
                        mOutgoingConnections.size(), mIncomingConnections.size());
    mMaxThreads = threads;
}

size_t RpcSession::getMaxThreads() {
    std::lock_guard<std::mutex> _l(mMutex);
    return mMaxThreads;
}

bool RpcSession::setProtocolVersion(uint32_t version) {
    if (version >= RPC_WIRE_PROTOCOL_VERSION_NEXT &&
        version != RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL) {
        ALOGE("Cannot start RPC session with version %u which is unknown (current protocol version "
              "is %u).",
              version, RPC_WIRE_PROTOCOL_VERSION);
        return false;
    }

    std::lock_guard<std::mutex> _l(mMutex);
    if (mProtocolVersion && version > *mProtocolVersion) {
        ALOGE("Cannot upgrade explicitly capped protocol version %u to newer version %u",
              *mProtocolVersion, version);
        return false;
    }

    mProtocolVersion = version;
    return true;
}

std::optional<uint32_t> RpcSession::getProtocolVersion() {
    std::lock_guard<std::mutex> _l(mMutex);
    return mProtocolVersion;
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

bool RpcSession::setupPreconnectedClient(unique_fd fd, std::function<unique_fd()>&& request) {
    return setupClient([&](const RpcAddress& sessionId, bool incoming) {
        // std::move'd from fd becomes -1 (!ok())
        if (!fd.ok()) {
            fd = request();
            if (!fd.ok()) return false;
        }
        return initAndAddConnection(std::move(fd), sessionId, incoming);
    });
}

bool RpcSession::addNullDebuggingClient() {
    // Note: only works on raw sockets.
    unique_fd serverFd(TEMP_FAILURE_RETRY(open("/dev/null", O_WRONLY | O_CLOEXEC)));

    if (serverFd == -1) {
        ALOGE("Could not connect to /dev/null: %s", strerror(errno));
        return false;
    }

    auto ctx = mRpcTransportCtxFactory->newClientCtx();
    if (ctx == nullptr) {
        ALOGE("Unable to create RpcTransportCtx for null debugging client");
        return false;
    }
    auto server = ctx->newTransport(std::move(serverFd));
    if (server == nullptr) {
        ALOGE("Unable to set up RpcTransport");
        return false;
    }
    return addOutgoingConnection(std::move(server), false);
}

sp<IBinder> RpcSession::getRootObject() {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return nullptr;
    return state()->getRootObject(connection.get(), sp<RpcSession>::fromExisting(this));
}

status_t RpcSession::getRemoteMaxThreads(size_t* maxThreads) {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return status;
    return state()->getMaxThreads(connection.get(), sp<RpcSession>::fromExisting(this), maxThreads);
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
    return state()->transact(connection.get(), binder, code, data,
                             sp<RpcSession>::fromExisting(this), reply, flags);
}

status_t RpcSession::sendDecStrong(const RpcAddress& address) {
    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT_REFCOUNT, &connection);
    if (status != OK) return status;
    return state()->sendDecStrong(connection.get(), sp<RpcSession>::fromExisting(this), address);
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

status_t RpcSession::FdTrigger::triggerablePoll(RpcTransport* rpcTransport, int16_t event) {
    return triggerablePoll(rpcTransport->pollSocket(), event);
}

status_t RpcSession::FdTrigger::triggerablePoll(base::borrowed_fd fd, int16_t event) {
    while (true) {
        pollfd pfd[]{{.fd = fd.get(), .events = static_cast<int16_t>(event), .revents = 0},
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
        return pfd[0].revents & event ? OK : DEAD_OBJECT;
    }
}

status_t RpcSession::FdTrigger::interruptableWriteFully(RpcTransport* rpcTransport,
                                                        const void* data, size_t size) {
    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(data);
    const uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    status_t status;
    while ((status = triggerablePoll(rpcTransport, POLLOUT)) == OK) {
        auto writeSize = rpcTransport->send(buffer, end - buffer);
        if (!writeSize.ok()) {
            LOG_RPC_DETAIL("RpcTransport::send(): %s", writeSize.error().message().c_str());
            return writeSize.error().code() == 0 ? UNKNOWN_ERROR : -writeSize.error().code();
        }

        if (*writeSize == 0) return DEAD_OBJECT;

        buffer += *writeSize;
        if (buffer == end) return OK;
    }
    return status;
}

status_t RpcSession::FdTrigger::interruptableReadFully(RpcTransport* rpcTransport, void* data,
                                                       size_t size) {
    uint8_t* buffer = reinterpret_cast<uint8_t*>(data);
    uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    status_t status;
    while ((status = triggerablePoll(rpcTransport, POLLIN)) == OK) {
        auto readSize = rpcTransport->recv(buffer, end - buffer);
        if (!readSize.ok()) {
            LOG_RPC_DETAIL("RpcTransport::recv(): %s", readSize.error().message().c_str());
            return readSize.error().code() == 0 ? UNKNOWN_ERROR : -readSize.error().code();
        }

        if (*readSize == 0) return DEAD_OBJECT; // EOF

        buffer += *readSize;
        if (buffer == end) return OK;
    }
    return status;
}

status_t RpcSession::readId() {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mForServer != nullptr, "Can only update ID for client.");
    }

    ExclusiveConnection connection;
    status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                ConnectionUse::CLIENT, &connection);
    if (status != OK) return status;

    mId = RpcAddress::zero();
    status = state()->getSessionId(connection.get(), sp<RpcSession>::fromExisting(this),
                                   &mId.value());
    if (status != OK) return status;

    LOG_RPC_DETAIL("RpcSession %p has id %s", this, mId->toString().c_str());
    return OK;
}

void RpcSession::WaitForShutdownListener::onSessionAllIncomingThreadsEnded(
        const sp<RpcSession>& session) {
    (void)session;
    mShutdown = true;
}

void RpcSession::WaitForShutdownListener::onSessionIncomingThreadEnded() {
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

RpcSession::PreJoinSetupResult RpcSession::preJoinSetup(
        std::unique_ptr<RpcTransport> rpcTransport) {
    // must be registered to allow arbitrary client code executing commands to
    // be able to do nested calls (we can't only read from it)
    sp<RpcConnection> connection = assignIncomingConnectionToThisThread(std::move(rpcTransport));

    status_t status;

    if (connection == nullptr) {
        status = DEAD_OBJECT;
    } else {
        status = mState->readConnectionInit(connection, sp<RpcSession>::fromExisting(this));
    }

    return PreJoinSetupResult{
            .connection = std::move(connection),
            .status = status,
    };
}

namespace {
// RAII object for attaching / detaching current thread to JVM if Android Runtime exists. If
// Android Runtime doesn't exist, no-op.
class JavaThreadAttacher {
public:
    JavaThreadAttacher() {
        // Use dlsym to find androidJavaAttachThread because libandroid_runtime is loaded after
        // libbinder.
        auto vm = getJavaVM();
        if (vm == nullptr) return;

        char threadName[16];
        if (0 != pthread_getname_np(pthread_self(), threadName, sizeof(threadName))) {
            constexpr const char* defaultThreadName = "UnknownRpcSessionThread";
            memcpy(threadName, defaultThreadName,
                   std::min<size_t>(sizeof(threadName), strlen(defaultThreadName) + 1));
        }
        LOG_RPC_DETAIL("Attaching current thread %s to JVM", threadName);
        JavaVMAttachArgs args;
        args.version = JNI_VERSION_1_2;
        args.name = threadName;
        args.group = nullptr;
        JNIEnv* env;

        LOG_ALWAYS_FATAL_IF(vm->AttachCurrentThread(&env, &args) != JNI_OK,
                            "Cannot attach thread %s to JVM", threadName);
        mAttached = true;
    }
    ~JavaThreadAttacher() {
        if (!mAttached) return;
        auto vm = getJavaVM();
        LOG_ALWAYS_FATAL_IF(vm == nullptr,
                            "Unable to detach thread. No JavaVM, but it was present before!");

        LOG_RPC_DETAIL("Detaching current thread from JVM");
        if (vm->DetachCurrentThread() != JNI_OK) {
            mAttached = false;
        } else {
            ALOGW("Unable to detach current thread from JVM");
        }
    }

private:
    DISALLOW_COPY_AND_ASSIGN(JavaThreadAttacher);
    bool mAttached = false;

    static JavaVM* getJavaVM() {
        static auto fn = reinterpret_cast<decltype(&AndroidRuntimeGetJavaVM)>(
                dlsym(RTLD_DEFAULT, "AndroidRuntimeGetJavaVM"));
        if (fn == nullptr) return nullptr;
        return fn();
    }
};
} // namespace

void RpcSession::join(sp<RpcSession>&& session, PreJoinSetupResult&& setupResult) {
    sp<RpcConnection>& connection = setupResult.connection;

    if (setupResult.status == OK) {
        LOG_ALWAYS_FATAL_IF(!connection, "must have connection if setup succeeded");
        JavaThreadAttacher javaThreadAttacher;
        while (true) {
            status_t status = session->state()->getAndExecuteCommand(connection, session,
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

    sp<RpcSession::EventListener> listener;
    {
        std::lock_guard<std::mutex> _l(session->mMutex);
        auto it = session->mThreads.find(std::this_thread::get_id());
        LOG_ALWAYS_FATAL_IF(it == session->mThreads.end());
        it->second.detach();
        session->mThreads.erase(it);

        listener = session->mEventListener.promote();
    }

    // done after all cleanup, since session shutdown progresses via callbacks here
    if (connection != nullptr) {
        LOG_ALWAYS_FATAL_IF(!session->removeIncomingConnection(connection),
                            "bad state: connection object guaranteed to be in list");
    }

    session = nullptr;

    if (listener != nullptr) {
        listener->onSessionIncomingThreadEnded();
    }
}

sp<RpcServer> RpcSession::server() {
    RpcServer* unsafeServer = mForServer.unsafe_get();
    sp<RpcServer> server = mForServer.promote();

    LOG_ALWAYS_FATAL_IF((unsafeServer == nullptr) != (server == nullptr),
                        "wp<> is to avoid strong cycle only");
    return server;
}

bool RpcSession::setupClient(
        const std::function<bool(const RpcAddress& sessionId, bool incoming)>& connectAndInit) {
    {
        std::lock_guard<std::mutex> _l(mMutex);
        LOG_ALWAYS_FATAL_IF(mOutgoingConnections.size() != 0,
                            "Must only setup session once, but already has %zu clients",
                            mOutgoingConnections.size());
    }

    if (!connectAndInit(RpcAddress::zero(), false /*incoming*/)) return false;

    {
        ExclusiveConnection connection;
        status_t status = ExclusiveConnection::find(sp<RpcSession>::fromExisting(this),
                                                    ConnectionUse::CLIENT, &connection);
        if (status != OK) return false;

        uint32_t version;
        status = state()->readNewSessionResponse(connection.get(),
                                                 sp<RpcSession>::fromExisting(this), &version);
        if (!setProtocolVersion(version)) return false;
    }

    // TODO(b/189955605): we should add additional sessions dynamically
    // instead of all at once.
    // TODO(b/186470974): first risk of blocking
    size_t numThreadsAvailable;
    if (status_t status = getRemoteMaxThreads(&numThreadsAvailable); status != OK) {
        ALOGE("Could not get max threads after initial session setup: %s",
              statusToString(status).c_str());
        return false;
    }

    if (status_t status = readId(); status != OK) {
        ALOGE("Could not get session id after initial session setup: %s",
              statusToString(status).c_str());
        return false;
    }

    // TODO(b/189955605): we should add additional sessions dynamically
    // instead of all at once - the other side should be responsible for setting
    // up additional connections. We need to create at least one (unless 0 are
    // requested to be set) in order to allow the other side to reliably make
    // any requests at all.

    // we've already setup one client
    for (size_t i = 0; i + 1 < numThreadsAvailable; i++) {
        if (!connectAndInit(mId.value(), false /*incoming*/)) return false;
    }

    for (size_t i = 0; i < mMaxThreads; i++) {
        if (!connectAndInit(mId.value(), true /*incoming*/)) return false;
    }

    return true;
}

bool RpcSession::setupSocketClient(const RpcSocketAddress& addr) {
    return setupClient([&](const RpcAddress& sessionId, bool incoming) {
        return setupOneSocketConnection(addr, sessionId, incoming);
    });
}

bool RpcSession::setupOneSocketConnection(const RpcSocketAddress& addr, const RpcAddress& sessionId,
                                          bool incoming) {
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
        LOG_RPC_DETAIL("Socket at %s client with fd %d", addr.toString().c_str(), serverFd.get());

        return initAndAddConnection(std::move(serverFd), sessionId, incoming);
    }

    ALOGE("Ran out of retries to connect to %s", addr.toString().c_str());
    return false;
}

bool RpcSession::initAndAddConnection(unique_fd fd, const RpcAddress& sessionId, bool incoming) {
    auto ctx = mRpcTransportCtxFactory->newClientCtx();
    if (ctx == nullptr) {
        ALOGE("Unable to create client RpcTransportCtx with %s sockets",
              mRpcTransportCtxFactory->toCString());
        return false;
    }
    auto server = ctx->newTransport(std::move(fd));
    if (server == nullptr) {
        ALOGE("Unable to set up RpcTransport in %s context", mRpcTransportCtxFactory->toCString());
        return false;
    }

    LOG_RPC_DETAIL("Socket at client with RpcTransport %p", server.get());

    RpcConnectionHeader header{
            .version = mProtocolVersion.value_or(RPC_WIRE_PROTOCOL_VERSION),
            .options = 0,
    };
    memcpy(&header.sessionId, &sessionId.viewRawEmbedded(), sizeof(RpcWireAddress));

    if (incoming) header.options |= RPC_CONNECTION_OPTION_INCOMING;

    auto sentHeader = server->send(&header, sizeof(header));
    if (!sentHeader.ok()) {
        ALOGE("Could not write connection header to socket: %s",
              sentHeader.error().message().c_str());
        return false;
    }
    if (*sentHeader != sizeof(header)) {
        ALOGE("Could not write connection header to socket: sent %zd bytes, expected %zd",
              *sentHeader, sizeof(header));
        return false;
    }

    LOG_RPC_DETAIL("Socket at client: header sent");

    if (incoming) {
        return addIncomingConnection(std::move(server));
    } else {
        return addOutgoingConnection(std::move(server), true /*init*/);
    }
}

bool RpcSession::addIncomingConnection(std::unique_ptr<RpcTransport> rpcTransport) {
    std::mutex mutex;
    std::condition_variable joinCv;
    std::unique_lock<std::mutex> lock(mutex);
    std::thread thread;
    sp<RpcSession> thiz = sp<RpcSession>::fromExisting(this);
    bool ownershipTransferred = false;
    thread = std::thread([&]() {
        std::unique_lock<std::mutex> threadLock(mutex);
        std::unique_ptr<RpcTransport> movedRpcTransport = std::move(rpcTransport);
        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
        sp<RpcSession> session = thiz;
        session->preJoinThreadOwnership(std::move(thread));

        // only continue once we have a response or the connection fails
        auto setupResult = session->preJoinSetup(std::move(movedRpcTransport));

        ownershipTransferred = true;
        threadLock.unlock();
        joinCv.notify_one();
        // do not use & vars below

        RpcSession::join(std::move(session), std::move(setupResult));
    });
    joinCv.wait(lock, [&] { return ownershipTransferred; });
    LOG_ALWAYS_FATAL_IF(!ownershipTransferred);
    return true;
}

bool RpcSession::addOutgoingConnection(std::unique_ptr<RpcTransport> rpcTransport, bool init) {
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

        connection->rpcTransport = std::move(rpcTransport);
        connection->exclusiveTid = gettid();
        mOutgoingConnections.push_back(connection);
    }

    status_t status = OK;
    if (init) {
        mState->sendConnectionInit(connection, sp<RpcSession>::fromExisting(this));
    }

    {
        std::lock_guard<std::mutex> _l(mMutex);
        connection->exclusiveTid = std::nullopt;
    }

    return status == OK;
}

bool RpcSession::setForServer(const wp<RpcServer>& server, const wp<EventListener>& eventListener,
                              const RpcAddress& sessionId) {
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

sp<RpcSession::RpcConnection> RpcSession::assignIncomingConnectionToThisThread(
        std::unique_ptr<RpcTransport> rpcTransport) {
    std::lock_guard<std::mutex> _l(mMutex);

    if (mIncomingConnections.size() >= mMaxThreads) {
        ALOGE("Cannot add thread to session with %zu threads (max is set to %zu)",
              mIncomingConnections.size(), mMaxThreads);
        return nullptr;
    }

    // Don't accept any more connections, some have shutdown. Usually this
    // happens when new connections are still being established as part of a
    // very short-lived session which shuts down after it already started
    // accepting new connections.
    if (mIncomingConnections.size() < mMaxIncomingConnections) {
        return nullptr;
    }

    sp<RpcConnection> session = sp<RpcConnection>::make();
    session->rpcTransport = std::move(rpcTransport);
    session->exclusiveTid = gettid();

    mIncomingConnections.push_back(session);
    mMaxIncomingConnections = mIncomingConnections.size();

    return session;
}

bool RpcSession::removeIncomingConnection(const sp<RpcConnection>& connection) {
    std::unique_lock<std::mutex> _l(mMutex);
    if (auto it = std::find(mIncomingConnections.begin(), mIncomingConnections.end(), connection);
        it != mIncomingConnections.end()) {
        mIncomingConnections.erase(it);
        if (mIncomingConnections.size() == 0) {
            sp<EventListener> listener = mEventListener.promote();
            if (listener) {
                _l.unlock();
                listener->onSessionAllIncomingThreadsEnded(sp<RpcSession>::fromExisting(this));
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
        findConnection(tid, &exclusive, &available, session->mOutgoingConnections,
                       session->mOutgoingConnectionsOffset);

        // WARNING: this assumes a server cannot request its client to send
        // a transaction, as mIncomingConnections is excluded below.
        //
        // Imagine we have more than one thread in play, and a single thread
        // sends a synchronous, then an asynchronous command. Imagine the
        // asynchronous command is sent on the first client connection. Then, if
        // we naively send a synchronous command to that same connection, the
        // thread on the far side might be busy processing the asynchronous
        // command. So, we move to considering the second available thread
        // for subsequent calls.
        if (use == ConnectionUse::CLIENT_ASYNC && (exclusive != nullptr || available != nullptr)) {
            session->mOutgoingConnectionsOffset = (session->mOutgoingConnectionsOffset + 1) %
                    session->mOutgoingConnections.size();
        }

        // USE SERVING SOCKET (e.g. nested transaction)
        if (use != ConnectionUse::CLIENT_ASYNC) {
            sp<RpcConnection> exclusiveIncoming;
            // server connections are always assigned to a thread
            findConnection(tid, &exclusiveIncoming, nullptr /*available*/,
                           session->mIncomingConnections, 0 /* index hint */);

            // asynchronous calls cannot be nested, we currently allow ref count
            // calls to be nested (so that you can use this without having extra
            // threads). Note 'drainCommands' is used so that these ref counts can't
            // build up.
            if (exclusiveIncoming != nullptr) {
                if (exclusiveIncoming->allowNested) {
                    // guaranteed to be processed as nested command
                    exclusive = exclusiveIncoming;
                } else if (use == ConnectionUse::CLIENT_REFCOUNT && available == nullptr) {
                    // prefer available socket, but if we don't have one, don't
                    // wait for one
                    exclusive = exclusiveIncoming;
                }
            }
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

        if (session->mOutgoingConnections.size() == 0) {
            ALOGE("Session has no client connections. This is required for an RPC server to make "
                  "any non-nested (e.g. oneway or on another thread) calls. Use: %d. Server "
                  "connections: %zu",
                  static_cast<int>(use), session->mIncomingConnections.size());
            return WOULD_BLOCK;
        }

        LOG_RPC_DETAIL("No available connections (have %zu clients and %zu servers). Waiting...",
                       session->mOutgoingConnections.size(), session->mIncomingConnections.size());
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
