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

#include <BnBinderRpcSession.h>
#include <BnBinderRpcTest.h>
#include <aidl/IBinderRpcTest.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android/binder_auto_utils.h>
#include <android/binder_libbinder.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#ifdef __BIONIC__
#include <linux/vm_sockets.h>
#endif //__BIONIC__

#include <sys/prctl.h>
#include <unistd.h>

#include "../RpcState.h" // for debugging

namespace android {

TEST(BinderRpcParcel, EntireParcelFormatted) {
    Parcel p;
    p.writeInt32(3);

    EXPECT_DEATH(p.markForBinder(sp<BBinder>::make()), "");
}

using android::binder::Status;

#define EXPECT_OK(status)                 \
    do {                                  \
        Status stat = (status);           \
        EXPECT_TRUE(stat.isOk()) << stat; \
    } while (false)

class MyBinderRpcSession : public BnBinderRpcSession {
public:
    static std::atomic<int32_t> gNum;

    MyBinderRpcSession(const std::string& name) : mName(name) { gNum++; }
    Status getName(std::string* name) override {
        *name = mName;
        return Status::ok();
    }
    ~MyBinderRpcSession() { gNum--; }

private:
    std::string mName;
};
std::atomic<int32_t> MyBinderRpcSession::gNum;

class MyBinderRpcTest : public BnBinderRpcTest {
public:
    wp<RpcServer> server;

    Status sendString(const std::string& str) override {
        (void)str;
        return Status::ok();
    }
    Status doubleString(const std::string& str, std::string* strstr) override {
        *strstr = str + str;
        return Status::ok();
    }
    Status countBinders(std::vector<int32_t>* out) override {
        sp<RpcServer> spServer = server.promote();
        if (spServer == nullptr) {
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        out->clear();
        for (auto session : spServer->listSessions()) {
            size_t count = session->state()->countBinders();
            if (count != 1) {
                // this is called when there is only one binder held remaining,
                // so to aid debugging
                session->state()->dump();
            }
            out->push_back(count);
        }
        return Status::ok();
    }
    Status pingMe(const sp<IBinder>& binder, int32_t* out) override {
        if (binder == nullptr) {
            std::cout << "Received null binder!" << std::endl;
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = binder->pingBinder();
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& binder, sp<IBinder>* out) override {
        *out = binder;
        return Status::ok();
    }
    static sp<IBinder> mHeldBinder;
    Status holdBinder(const sp<IBinder>& binder) override {
        mHeldBinder = binder;
        return Status::ok();
    }
    Status getHeldBinder(sp<IBinder>* held) override {
        *held = mHeldBinder;
        return Status::ok();
    }
    Status nestMe(const sp<IBinderRpcTest>& binder, int count) override {
        if (count <= 0) return Status::ok();
        return binder->nestMe(this, count - 1);
    }
    Status alwaysGiveMeTheSameBinder(sp<IBinder>* out) override {
        static sp<IBinder> binder = new BBinder;
        *out = binder;
        return Status::ok();
    }
    Status openSession(const std::string& name, sp<IBinderRpcSession>* out) override {
        *out = new MyBinderRpcSession(name);
        return Status::ok();
    }
    Status getNumOpenSessions(int32_t* out) override {
        *out = MyBinderRpcSession::gNum;
        return Status::ok();
    }

    std::mutex blockMutex;
    Status lock() override {
        blockMutex.lock();
        return Status::ok();
    }
    Status unlockInMsAsync(int32_t ms) override {
        usleep(ms * 1000);
        blockMutex.unlock();
        return Status::ok();
    }
    Status lockUnlock() override {
        std::lock_guard<std::mutex> _l(blockMutex);
        return Status::ok();
    }

    Status sleepMs(int32_t ms) override {
        usleep(ms * 1000);
        return Status::ok();
    }

    Status sleepMsAsync(int32_t ms) override {
        // In-process binder calls are asynchronous, but the call to this method
        // is synchronous wrt its client. This in/out-process threading model
        // diffentiation is a classic binder leaky abstraction (for better or
        // worse) and is preserved here the way binder sockets plugs itself
        // into BpBinder, as nothing is changed at the higher levels
        // (IInterface) which result in this behavior.
        return sleepMs(ms);
    }

    Status die(bool cleanup) override {
        if (cleanup) {
            exit(1);
        } else {
            _exit(1);
        }
    }
};
sp<IBinder> MyBinderRpcTest::mHeldBinder;

class Pipe {
public:
    Pipe() { CHECK(android::base::Pipe(&mRead, &mWrite)); }
    Pipe(Pipe&&) = default;
    android::base::borrowed_fd readEnd() { return mRead; }
    android::base::borrowed_fd writeEnd() { return mWrite; }

private:
    android::base::unique_fd mRead;
    android::base::unique_fd mWrite;
};

class Process {
public:
    Process(Process&&) = default;
    Process(const std::function<void(Pipe*)>& f) {
        if (0 == (mPid = fork())) {
            // racey: assume parent doesn't crash before this is set
            prctl(PR_SET_PDEATHSIG, SIGHUP);

            f(&mPipe);
        }
    }
    ~Process() {
        if (mPid != 0) {
            kill(mPid, SIGKILL);
        }
    }
    Pipe* getPipe() { return &mPipe; }

private:
    pid_t mPid = 0;
    Pipe mPipe;
};

static std::string allocateSocketAddress() {
    static size_t id = 0;
    std::string temp = getenv("TMPDIR") ?: "/tmp";
    return temp + "/binderRpcTest_" + std::to_string(id++);
};

struct ProcessSession {
    // reference to process hosting a socket server
    Process host;

    struct SessionInfo {
        sp<RpcSession> session;
        sp<IBinder> root;
    };

    // client session objects associated with other process
    // each one represents a separate session
    std::vector<SessionInfo> sessions;

    ProcessSession(ProcessSession&&) = default;
    ~ProcessSession() {
        for (auto& session : sessions) {
            session.root = nullptr;
        }

        for (auto& info : sessions) {
            sp<RpcSession>& session = info.session;

            EXPECT_NE(nullptr, session);
            EXPECT_NE(nullptr, session->state());
            EXPECT_EQ(0, session->state()->countBinders()) << (session->state()->dump(), "dump:");

            wp<RpcSession> weakSession = session;
            session = nullptr;
            EXPECT_EQ(nullptr, weakSession.promote()) << "Leaked session";
        }
    }
};

// Process session where the process hosts IBinderRpcTest, the server used
// for most testing here
struct BinderRpcTestProcessSession {
    ProcessSession proc;

    // pre-fetched root object (for first session)
    sp<IBinder> rootBinder;

    // pre-casted root object (for first session)
    sp<IBinderRpcTest> rootIface;

    // whether session should be invalidated by end of run
    bool expectInvalid = false;

    BinderRpcTestProcessSession(BinderRpcTestProcessSession&&) = default;
    ~BinderRpcTestProcessSession() {
        if (!expectInvalid) {
            std::vector<int32_t> remoteCounts;
            // calling over any sessions counts across all sessions
            EXPECT_OK(rootIface->countBinders(&remoteCounts));
            EXPECT_EQ(remoteCounts.size(), proc.sessions.size());
            for (auto remoteCount : remoteCounts) {
                EXPECT_EQ(remoteCount, 1);
            }
        }

        rootIface = nullptr;
        rootBinder = nullptr;
    }
};

enum class SocketType {
    UNIX,
#ifdef __BIONIC__
    VSOCK,
#endif // __BIONIC__
    INET,
};
static inline std::string PrintSocketType(const testing::TestParamInfo<SocketType>& info) {
    switch (info.param) {
        case SocketType::UNIX:
            return "unix_domain_socket";
#ifdef __BIONIC__
        case SocketType::VSOCK:
            return "vm_socket";
#endif // __BIONIC__
        case SocketType::INET:
            return "inet_socket";
        default:
            LOG_ALWAYS_FATAL("Unknown socket type");
            return "";
    }
}
class BinderRpc : public ::testing::TestWithParam<SocketType> {
public:
    // This creates a new process serving an interface on a certain number of
    // threads.
    ProcessSession createRpcTestSocketServerProcess(
            size_t numThreads, size_t numSessions,
            const std::function<void(const sp<RpcServer>&)>& configure) {
        CHECK_GE(numSessions, 1) << "Must have at least one session to a server";

        SocketType socketType = GetParam();

        std::string addr = allocateSocketAddress();
        unlink(addr.c_str());
        static unsigned int vsockPort = 3456;
        vsockPort++;

        auto ret = ProcessSession{
                .host = Process([&](Pipe* pipe) {
                    sp<RpcServer> server = RpcServer::make();

                    server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
                    server->setMaxThreads(numThreads);

                    switch (socketType) {
                        case SocketType::UNIX:
                            CHECK(server->setupUnixDomainServer(addr.c_str())) << addr;
                            break;
#ifdef __BIONIC__
                        case SocketType::VSOCK:
                            CHECK(server->setupVsockServer(vsockPort));
                            break;
#endif // __BIONIC__
                        case SocketType::INET: {
                            unsigned int outPort = 0;
                            CHECK(server->setupInetServer(0, &outPort));
                            CHECK_NE(0, outPort);
                            CHECK(android::base::WriteFully(pipe->writeEnd(), &outPort,
                                                            sizeof(outPort)));
                            break;
                        }
                        default:
                            LOG_ALWAYS_FATAL("Unknown socket type");
                    }

                    configure(server);

                    server->join();
                }),
        };

        unsigned int inetPort = 0;
        if (socketType == SocketType::INET) {
            CHECK(android::base::ReadFully(ret.host.getPipe()->readEnd(), &inetPort,
                                           sizeof(inetPort)));
            CHECK_NE(0, inetPort);
        }

        for (size_t i = 0; i < numSessions; i++) {
            sp<RpcSession> session = RpcSession::make();
            for (size_t tries = 0; tries < 10; tries++) {
                usleep(10000);
                switch (socketType) {
                    case SocketType::UNIX:
                        if (session->setupUnixDomainClient(addr.c_str())) goto success;
                        break;
#ifdef __BIONIC__
                    case SocketType::VSOCK:
                        if (session->setupVsockClient(VMADDR_CID_LOCAL, vsockPort)) goto success;
                        break;
#endif // __BIONIC__
                    case SocketType::INET:
                        if (session->setupInetClient("127.0.0.1", inetPort)) goto success;
                        break;
                    default:
                        LOG_ALWAYS_FATAL("Unknown socket type");
                }
            }
            LOG_ALWAYS_FATAL("Could not connect");
        success:
            ret.sessions.push_back({session, session->getRootObject()});
        }
        return ret;
    }

    BinderRpcTestProcessSession createRpcTestSocketServerProcess(size_t numThreads,
                                                                 size_t numSessions = 1) {
        BinderRpcTestProcessSession ret{
                .proc = createRpcTestSocketServerProcess(numThreads, numSessions,
                                                         [&](const sp<RpcServer>& server) {
                                                             sp<MyBinderRpcTest> service =
                                                                     new MyBinderRpcTest;
                                                             server->setRootObject(service);
                                                             service->server = server;
                                                         }),
        };

        ret.rootBinder = ret.proc.sessions.at(0).root;
        ret.rootIface = interface_cast<IBinderRpcTest>(ret.rootBinder);

        return ret;
    }
};

TEST_P(BinderRpc, RootObjectIsNull) {
    auto proc = createRpcTestSocketServerProcess(1, 1, [](const sp<RpcServer>& server) {
        // this is the default, but to be explicit
        server->setRootObject(nullptr);
    });

    EXPECT_EQ(nullptr, proc.sessions.at(0).root);
}

TEST_P(BinderRpc, Ping) {
    auto proc = createRpcTestSocketServerProcess(1);
    ASSERT_NE(proc.rootBinder, nullptr);
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());
}

TEST_P(BinderRpc, GetInterfaceDescriptor) {
    auto proc = createRpcTestSocketServerProcess(1);
    ASSERT_NE(proc.rootBinder, nullptr);
    EXPECT_EQ(IBinderRpcTest::descriptor, proc.rootBinder->getInterfaceDescriptor());
}

TEST_P(BinderRpc, MultipleSessions) {
    auto proc = createRpcTestSocketServerProcess(1 /*threads*/, 5 /*sessions*/);
    for (auto session : proc.proc.sessions) {
        ASSERT_NE(nullptr, session.root);
        EXPECT_EQ(OK, session.root->pingBinder());
    }
}

TEST_P(BinderRpc, TransactionsMustBeMarkedRpc) {
    auto proc = createRpcTestSocketServerProcess(1);
    Parcel data;
    Parcel reply;
    EXPECT_EQ(BAD_TYPE, proc.rootBinder->transact(IBinder::PING_TRANSACTION, data, &reply, 0));
}

TEST_P(BinderRpc, AppendSeparateFormats) {
    auto proc = createRpcTestSocketServerProcess(1);

    Parcel p1;
    p1.markForBinder(proc.rootBinder);
    p1.writeInt32(3);

    Parcel p2;

    EXPECT_EQ(BAD_TYPE, p1.appendFrom(&p2, 0, p2.dataSize()));
    EXPECT_EQ(BAD_TYPE, p2.appendFrom(&p1, 0, p1.dataSize()));
}

TEST_P(BinderRpc, UnknownTransaction) {
    auto proc = createRpcTestSocketServerProcess(1);
    Parcel data;
    data.markForBinder(proc.rootBinder);
    Parcel reply;
    EXPECT_EQ(UNKNOWN_TRANSACTION, proc.rootBinder->transact(1337, data, &reply, 0));
}

TEST_P(BinderRpc, SendSomethingOneway) {
    auto proc = createRpcTestSocketServerProcess(1);
    EXPECT_OK(proc.rootIface->sendString("asdf"));
}

TEST_P(BinderRpc, SendAndGetResultBack) {
    auto proc = createRpcTestSocketServerProcess(1);
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

TEST_P(BinderRpc, SendAndGetResultBackBig) {
    auto proc = createRpcTestSocketServerProcess(1);
    std::string single = std::string(1024, 'a');
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString(single, &doubled));
    EXPECT_EQ(single + single, doubled);
}

TEST_P(BinderRpc, CallMeBack) {
    auto proc = createRpcTestSocketServerProcess(1);

    int32_t pingResult;
    EXPECT_OK(proc.rootIface->pingMe(new MyBinderRpcSession("foo"), &pingResult));
    EXPECT_EQ(OK, pingResult);

    EXPECT_EQ(0, MyBinderRpcSession::gNum);
}

TEST_P(BinderRpc, RepeatBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> inBinder = new MyBinderRpcSession("foo");
    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(inBinder, &outBinder));
    EXPECT_EQ(inBinder, outBinder);

    wp<IBinder> weak = inBinder;
    inBinder = nullptr;
    outBinder = nullptr;

    // Force reading a reply, to process any pending dec refs from the other
    // process (the other process will process dec refs there before processing
    // the ping here).
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    EXPECT_EQ(nullptr, weak.promote());

    EXPECT_EQ(0, MyBinderRpcSession::gNum);
}

TEST_P(BinderRpc, RepeatTheirBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinderRpcSession> session;
    EXPECT_OK(proc.rootIface->openSession("aoeu", &session));

    sp<IBinder> inBinder = IInterface::asBinder(session);
    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(inBinder, &outBinder));
    EXPECT_EQ(inBinder, outBinder);

    wp<IBinder> weak = inBinder;
    session = nullptr;
    inBinder = nullptr;
    outBinder = nullptr;

    // Force reading a reply, to process any pending dec refs from the other
    // process (the other process will process dec refs there before processing
    // the ping here).
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    EXPECT_EQ(nullptr, weak.promote());
}

TEST_P(BinderRpc, RepeatBinderNull) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(nullptr, &outBinder));
    EXPECT_EQ(nullptr, outBinder);
}

TEST_P(BinderRpc, HoldBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    IBinder* ptr = nullptr;
    {
        sp<IBinder> binder = new BBinder();
        ptr = binder.get();
        EXPECT_OK(proc.rootIface->holdBinder(binder));
    }

    sp<IBinder> held;
    EXPECT_OK(proc.rootIface->getHeldBinder(&held));

    EXPECT_EQ(held.get(), ptr);

    // stop holding binder, because we test to make sure references are cleaned
    // up
    EXPECT_OK(proc.rootIface->holdBinder(nullptr));
    // and flush ref counts
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());
}

// START TESTS FOR LIMITATIONS OF SOCKET BINDER
// These are behavioral differences form regular binder, where certain usecases
// aren't supported.

TEST_P(BinderRpc, CannotMixBindersBetweenUnrelatedSocketSessions) {
    auto proc1 = createRpcTestSocketServerProcess(1);
    auto proc2 = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc1.rootIface->repeatBinder(proc2.rootBinder, &outBinder).transactionError());
}

TEST_P(BinderRpc, CannotMixBindersBetweenTwoSessionsToTheSameServer) {
    auto proc = createRpcTestSocketServerProcess(1 /*threads*/, 2 /*sessions*/);

    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc.rootIface->repeatBinder(proc.proc.sessions.at(1).root, &outBinder)
                      .transactionError());
}

TEST_P(BinderRpc, CannotSendRegularBinderOverSocketBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> someRealBinder = IInterface::asBinder(defaultServiceManager());
    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc.rootIface->repeatBinder(someRealBinder, &outBinder).transactionError());
}

TEST_P(BinderRpc, CannotSendSocketBinderOverRegularBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    // for historical reasons, IServiceManager interface only returns the
    // exception code
    EXPECT_EQ(binder::Status::EX_TRANSACTION_FAILED,
              defaultServiceManager()->addService(String16("not_suspicious"), proc.rootBinder));
}

// END TESTS FOR LIMITATIONS OF SOCKET BINDER

TEST_P(BinderRpc, RepeatRootObject) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(proc.rootBinder, &outBinder));
    EXPECT_EQ(proc.rootBinder, outBinder);
}

TEST_P(BinderRpc, NestedTransactions) {
    auto proc = createRpcTestSocketServerProcess(1);

    auto nastyNester = sp<MyBinderRpcTest>::make();
    EXPECT_OK(proc.rootIface->nestMe(nastyNester, 10));

    wp<IBinder> weak = nastyNester;
    nastyNester = nullptr;
    EXPECT_EQ(nullptr, weak.promote());
}

TEST_P(BinderRpc, SameBinderEquality) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> a;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&a));

    sp<IBinder> b;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&b));

    EXPECT_EQ(a, b);
}

TEST_P(BinderRpc, SameBinderEqualityWeak) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> a;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&a));
    wp<IBinder> weak = a;
    a = nullptr;

    sp<IBinder> b;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&b));

    // this is the wrong behavior, since BpBinder
    // doesn't implement onIncStrongAttempted
    // but make sure there is no crash
    EXPECT_EQ(nullptr, weak.promote());

    GTEST_SKIP() << "Weak binders aren't currently re-promotable for RPC binder.";

    // In order to fix this:
    // - need to have incStrongAttempted reflected across IPC boundary (wait for
    //   response to promote - round trip...)
    // - sendOnLastWeakRef, to delete entries out of RpcState table
    EXPECT_EQ(b, weak.promote());
}

#define expectSessions(expected, iface)                   \
    do {                                                  \
        int session;                                      \
        EXPECT_OK((iface)->getNumOpenSessions(&session)); \
        EXPECT_EQ(expected, session);                     \
    } while (false)

TEST_P(BinderRpc, SingleSession) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinderRpcSession> session;
    EXPECT_OK(proc.rootIface->openSession("aoeu", &session));
    std::string out;
    EXPECT_OK(session->getName(&out));
    EXPECT_EQ("aoeu", out);

    expectSessions(1, proc.rootIface);
    session = nullptr;
    expectSessions(0, proc.rootIface);
}

TEST_P(BinderRpc, ManySessions) {
    auto proc = createRpcTestSocketServerProcess(1);

    std::vector<sp<IBinderRpcSession>> sessions;

    for (size_t i = 0; i < 15; i++) {
        expectSessions(i, proc.rootIface);
        sp<IBinderRpcSession> session;
        EXPECT_OK(proc.rootIface->openSession(std::to_string(i), &session));
        sessions.push_back(session);
    }
    expectSessions(sessions.size(), proc.rootIface);
    for (size_t i = 0; i < sessions.size(); i++) {
        std::string out;
        EXPECT_OK(sessions.at(i)->getName(&out));
        EXPECT_EQ(std::to_string(i), out);
    }
    expectSessions(sessions.size(), proc.rootIface);

    while (!sessions.empty()) {
        sessions.pop_back();
        expectSessions(sessions.size(), proc.rootIface);
    }
    expectSessions(0, proc.rootIface);
}

size_t epochMillis() {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    using std::chrono::seconds;
    using std::chrono::system_clock;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

TEST_P(BinderRpc, ThreadPoolGreaterThanEqualRequested) {
    constexpr size_t kNumThreads = 10;

    auto proc = createRpcTestSocketServerProcess(kNumThreads);

    EXPECT_OK(proc.rootIface->lock());

    // block all but one thread taking locks
    std::vector<std::thread> ts;
    for (size_t i = 0; i < kNumThreads - 1; i++) {
        ts.push_back(std::thread([&] { proc.rootIface->lockUnlock(); }));
    }

    usleep(100000); // give chance for calls on other threads

    // other calls still work
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    constexpr size_t blockTimeMs = 500;
    size_t epochMsBefore = epochMillis();
    // after this, we should never see a response within this time
    EXPECT_OK(proc.rootIface->unlockInMsAsync(blockTimeMs));

    // this call should be blocked for blockTimeMs
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());

    size_t epochMsAfter = epochMillis();
    EXPECT_GE(epochMsAfter, epochMsBefore + blockTimeMs) << epochMsBefore;

    for (auto& t : ts) t.join();
}

TEST_P(BinderRpc, ThreadPoolOverSaturated) {
    constexpr size_t kNumThreads = 10;
    constexpr size_t kNumCalls = kNumThreads + 3;
    constexpr size_t kSleepMs = 500;

    auto proc = createRpcTestSocketServerProcess(kNumThreads);

    size_t epochMsBefore = epochMillis();

    std::vector<std::thread> ts;
    for (size_t i = 0; i < kNumCalls; i++) {
        ts.push_back(std::thread([&] { proc.rootIface->sleepMs(kSleepMs); }));
    }

    for (auto& t : ts) t.join();

    size_t epochMsAfter = epochMillis();

    EXPECT_GE(epochMsAfter, epochMsBefore + 2 * kSleepMs);

    // Potential flake, but make sure calls are handled in parallel.
    EXPECT_LE(epochMsAfter, epochMsBefore + 3 * kSleepMs);
}

TEST_P(BinderRpc, ThreadingStressTest) {
    constexpr size_t kNumClientThreads = 10;
    constexpr size_t kNumServerThreads = 10;
    constexpr size_t kNumCalls = 100;

    auto proc = createRpcTestSocketServerProcess(kNumServerThreads);

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClientThreads; i++) {
        threads.push_back(std::thread([&] {
            for (size_t j = 0; j < kNumCalls; j++) {
                sp<IBinder> out;
                EXPECT_OK(proc.rootIface->repeatBinder(proc.rootBinder, &out));
                EXPECT_EQ(proc.rootBinder, out);
            }
        }));
    }

    for (auto& t : threads) t.join();
}

TEST_P(BinderRpc, OnewayStressTest) {
    constexpr size_t kNumClientThreads = 10;
    constexpr size_t kNumServerThreads = 10;
    constexpr size_t kNumCalls = 100;

    auto proc = createRpcTestSocketServerProcess(kNumServerThreads);

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClientThreads; i++) {
        threads.push_back(std::thread([&] {
            for (size_t j = 0; j < kNumCalls; j++) {
                EXPECT_OK(proc.rootIface->sendString("a"));
            }

            // check threads are not stuck
            EXPECT_OK(proc.rootIface->sleepMs(250));
        }));
    }

    for (auto& t : threads) t.join();
}

TEST_P(BinderRpc, OnewayCallDoesNotWait) {
    constexpr size_t kReallyLongTimeMs = 100;
    constexpr size_t kSleepMs = kReallyLongTimeMs * 5;

    // more than one thread, just so this doesn't deadlock
    auto proc = createRpcTestSocketServerProcess(2);

    size_t epochMsBefore = epochMillis();

    EXPECT_OK(proc.rootIface->sleepMsAsync(kSleepMs));

    size_t epochMsAfter = epochMillis();
    EXPECT_LT(epochMsAfter, epochMsBefore + kReallyLongTimeMs);
}

TEST_P(BinderRpc, OnewayCallQueueing) {
    constexpr size_t kNumSleeps = 10;
    constexpr size_t kNumExtraServerThreads = 4;
    constexpr size_t kSleepMs = 50;

    // make sure calls to the same object happen on the same thread
    auto proc = createRpcTestSocketServerProcess(1 + kNumExtraServerThreads);

    EXPECT_OK(proc.rootIface->lock());

    for (size_t i = 0; i < kNumSleeps; i++) {
        // these should be processed serially
        proc.rootIface->sleepMsAsync(kSleepMs);
    }
    // should also be processesed serially
    EXPECT_OK(proc.rootIface->unlockInMsAsync(kSleepMs));

    size_t epochMsBefore = epochMillis();
    EXPECT_OK(proc.rootIface->lockUnlock());
    size_t epochMsAfter = epochMillis();

    EXPECT_GT(epochMsAfter, epochMsBefore + kSleepMs * kNumSleeps);
}

TEST_P(BinderRpc, Die) {
    for (bool doDeathCleanup : {true, false}) {
        auto proc = createRpcTestSocketServerProcess(1);

        // make sure there is some state during crash
        // 1. we hold their binder
        sp<IBinderRpcSession> session;
        EXPECT_OK(proc.rootIface->openSession("happy", &session));
        // 2. they hold our binder
        sp<IBinder> binder = new BBinder();
        EXPECT_OK(proc.rootIface->holdBinder(binder));

        EXPECT_EQ(DEAD_OBJECT, proc.rootIface->die(doDeathCleanup).transactionError())
                << "Do death cleanup: " << doDeathCleanup;

        proc.expectInvalid = true;
    }
}

TEST_P(BinderRpc, WorksWithLibbinderNdkPing) {
    auto proc = createRpcTestSocketServerProcess(1);

    ndk::SpAIBinder binder = ndk::SpAIBinder(AIBinder_fromPlatformBinder(proc.rootBinder));
    ASSERT_NE(binder, nullptr);

    ASSERT_EQ(STATUS_OK, AIBinder_ping(binder.get()));
}

TEST_P(BinderRpc, WorksWithLibbinderNdkUserTransaction) {
    auto proc = createRpcTestSocketServerProcess(1);

    ndk::SpAIBinder binder = ndk::SpAIBinder(AIBinder_fromPlatformBinder(proc.rootBinder));
    ASSERT_NE(binder, nullptr);

    auto ndkBinder = aidl::IBinderRpcTest::fromBinder(binder);
    ASSERT_NE(ndkBinder, nullptr);

    std::string out;
    ndk::ScopedAStatus status = ndkBinder->doubleString("aoeu", &out);
    ASSERT_TRUE(status.isOk()) << status.getDescription();
    ASSERT_EQ("aoeuaoeu", out);
}

ssize_t countFds() {
    DIR* dir = opendir("/proc/self/fd/");
    if (dir == nullptr) return -1;
    ssize_t ret = 0;
    dirent* ent;
    while ((ent = readdir(dir)) != nullptr) ret++;
    closedir(dir);
    return ret;
}

TEST_P(BinderRpc, Fds) {
    ssize_t beforeFds = countFds();
    ASSERT_GE(beforeFds, 0);
    {
        auto proc = createRpcTestSocketServerProcess(10);
        ASSERT_EQ(OK, proc.rootBinder->pingBinder());
    }
    ASSERT_EQ(beforeFds, countFds()) << (system("ls -l /proc/self/fd/"), "fd leak?");
}

INSTANTIATE_TEST_CASE_P(PerSocket, BinderRpc,
                        ::testing::ValuesIn({
                                SocketType::UNIX,
#ifdef __BIONIC__
                                SocketType::VSOCK,
#endif // __BIONIC__
                                SocketType::INET,
                        }),
                        PrintSocketType);

} // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::base::InitLogging(argv, android::base::StderrLogger, android::base::DefaultAborter);
    return RUN_ALL_TESTS();
}
