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

#include <sys/prctl.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

#include <BnBinderRpcSession.h>
#include <BnBinderRpcTest.h>
#include <android-base/logging.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <binder/RpcConnection.h>
#include <binder/RpcServer.h>
#include <gtest/gtest.h>

#include "../RpcState.h" // for debugging

namespace android {

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
    sp<RpcConnection> connection;

    Status sendString(const std::string& str) override {
        std::cout << "Child received string: " << str << std::endl;
        return Status::ok();
    }
    Status doubleString(const std::string& str, std::string* strstr) override {
        std::cout << "Child received string to double: " << str << std::endl;
        *strstr = str + str;
        return Status::ok();
    }
    Status countBinders(int32_t* out) override {
        if (connection == nullptr) {
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = connection->state()->countBinders();
        if (*out != 1) {
            connection->state()->dump();
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

class Process {
public:
    Process(const std::function<void()>& f) {
        if (0 == (mPid = fork())) {
            // racey: assume parent doesn't crash before this is set
            prctl(PR_SET_PDEATHSIG, SIGHUP);

            f();
        }
    }
    ~Process() {
        if (mPid != 0) {
            kill(mPid, SIGKILL);
        }
    }

private:
    pid_t mPid = 0;
};

static std::string allocateSocketAddress() {
    static size_t id = 0;

    return "/dev/binderRpcTest_" + std::to_string(id++);
};

struct ProcessConnection {
    // reference to process hosting a socket server
    Process host;

    // client connection object associated with other process
    sp<RpcConnection> connection;

    // pre-fetched root object
    sp<IBinder> rootBinder;

    // whether connection should be invalidated by end of run
    bool expectInvalid = false;

    ~ProcessConnection() {
        rootBinder = nullptr;
        EXPECT_NE(nullptr, connection);
        EXPECT_NE(nullptr, connection->state());
        EXPECT_EQ(0, connection->state()->countBinders()) << (connection->state()->dump(), "dump:");

        wp<RpcConnection> weakConnection = connection;
        connection = nullptr;
        EXPECT_EQ(nullptr, weakConnection.promote()) << "Leaked connection";
    }
};

// This creates a new process serving an interface on a certain number of
// threads.
ProcessConnection createRpcTestSocketServerProcess(
        size_t numThreads,
        const std::function<void(const sp<RpcServer>&, const sp<RpcConnection>&)>& configure) {
    CHECK_GT(numThreads, 0);

    std::string addr = allocateSocketAddress();
    unlink(addr.c_str());

    auto ret = ProcessConnection{
            .host = Process([&] {
                sp<RpcServer> server = RpcServer::make();

                server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();

                // server supporting one client on one socket
                sp<RpcConnection> connection = server->addClientConnection();
                CHECK(connection->setupUnixDomainServer(addr.c_str())) << addr;

                configure(server, connection);

                // accept 'numThreads' connections
                std::vector<std::thread> pool;
                for (size_t i = 0; i + 1 < numThreads; i++) {
                    pool.push_back(std::thread([=] { connection->join(); }));
                }
                connection->join();
                for (auto& t : pool) t.join();
            }),
            .connection = RpcConnection::make(),
    };

    // wait up to 1s for sockets to be created
    constexpr useconds_t kMaxWaitUs = 1000000;
    constexpr useconds_t kWaitDivision = 100;
    for (size_t i = 0; i < kWaitDivision && 0 != access(addr.c_str(), F_OK); i++) {
        usleep(kMaxWaitUs / kWaitDivision);
    }

    // create remainder of connections
    for (size_t i = 0; i < numThreads; i++) {
        // Connection refused sometimes after file created but before listening.
        CHECK(ret.connection->addUnixDomainClient(addr.c_str()) ||
              (usleep(10000), ret.connection->addUnixDomainClient(addr.c_str())))
                << i;
    }

    ret.rootBinder = ret.connection->getRootObject();
    return ret;
}

// Process connection where the process hosts IBinderRpcTest, the server used
// for most testing here
struct BinderRpcTestProcessConnection {
    ProcessConnection proc;

    // pre-fetched root object
    sp<IBinder> rootBinder;

    // pre-casted root object
    sp<IBinderRpcTest> rootIface;

    ~BinderRpcTestProcessConnection() {
        if (!proc.expectInvalid) {
            int32_t remoteBinders = 0;
            EXPECT_OK(rootIface->countBinders(&remoteBinders));
            // should only be the root binder object, iface
            EXPECT_EQ(remoteBinders, 1);
        }

        rootIface = nullptr;
        rootBinder = nullptr;
    }
};

BinderRpcTestProcessConnection createRpcTestSocketServerProcess(size_t numThreads) {
    BinderRpcTestProcessConnection ret{
            .proc = createRpcTestSocketServerProcess(numThreads,
                                                     [&](const sp<RpcServer>& server,
                                                         const sp<RpcConnection>& connection) {
                                                         sp<MyBinderRpcTest> service =
                                                                 new MyBinderRpcTest;
                                                         server->setRootObject(service);
                                                         service->connection =
                                                                 connection; // for testing only
                                                     }),
    };

    ret.rootBinder = ret.proc.rootBinder;
    ret.rootIface = interface_cast<IBinderRpcTest>(ret.rootBinder);

    return ret;
}

TEST(BinderRpc, RootObjectIsNull) {
    auto proc = createRpcTestSocketServerProcess(1,
                                                 [](const sp<RpcServer>& server,
                                                    const sp<RpcConnection>&) {
                                                     // this is the default, but to be explicit
                                                     server->setRootObject(nullptr);
                                                 });

    // retrieved by getRootObject when process is created above
    EXPECT_EQ(nullptr, proc.rootBinder);

    // make sure we can retrieve it again (process doesn't crash)
    EXPECT_EQ(nullptr, proc.connection->getRootObject());
}

TEST(BinderRpc, Ping) {
    auto proc = createRpcTestSocketServerProcess(1);
    ASSERT_NE(proc.rootBinder, nullptr);
    EXPECT_EQ(OK, proc.rootBinder->pingBinder());
}

TEST(BinderRpc, TransactionsMustBeMarkedRpc) {
    auto proc = createRpcTestSocketServerProcess(1);
    Parcel data;
    Parcel reply;
    EXPECT_EQ(BAD_TYPE, proc.rootBinder->transact(IBinder::PING_TRANSACTION, data, &reply, 0));
}

TEST(BinderRpc, UnknownTransaction) {
    auto proc = createRpcTestSocketServerProcess(1);
    Parcel data;
    data.markForBinder(proc.rootBinder);
    Parcel reply;
    EXPECT_EQ(UNKNOWN_TRANSACTION, proc.rootBinder->transact(1337, data, &reply, 0));
}

TEST(BinderRpc, SendSomethingOneway) {
    auto proc = createRpcTestSocketServerProcess(1);
    EXPECT_OK(proc.rootIface->sendString("asdf"));
}

TEST(BinderRpc, SendAndGetResultBack) {
    auto proc = createRpcTestSocketServerProcess(1);
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString("cool ", &doubled));
    EXPECT_EQ("cool cool ", doubled);
}

TEST(BinderRpc, SendAndGetResultBackBig) {
    auto proc = createRpcTestSocketServerProcess(1);
    std::string single = std::string(1024, 'a');
    std::string doubled;
    EXPECT_OK(proc.rootIface->doubleString(single, &doubled));
    EXPECT_EQ(single + single, doubled);
}

TEST(BinderRpc, CallMeBack) {
    auto proc = createRpcTestSocketServerProcess(1);

    int32_t pingResult;
    EXPECT_OK(proc.rootIface->pingMe(new MyBinderRpcSession("foo"), &pingResult));
    EXPECT_EQ(OK, pingResult);

    EXPECT_EQ(0, MyBinderRpcSession::gNum);
}

TEST(BinderRpc, RepeatBinder) {
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

TEST(BinderRpc, RepeatTheirBinder) {
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

TEST(BinderRpc, RepeatBinderNull) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(nullptr, &outBinder));
    EXPECT_EQ(nullptr, outBinder);
}

TEST(BinderRpc, HoldBinder) {
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

TEST(BinderRpc, CannotMixBindersBetweenUnrelatedSocketConnections) {
    auto proc1 = createRpcTestSocketServerProcess(1);
    auto proc2 = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc1.rootIface->repeatBinder(proc2.rootBinder, &outBinder).transactionError());
}

TEST(BinderRpc, CannotSendRegularBinderOverSocketBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> someRealBinder = IInterface::asBinder(defaultServiceManager());
    sp<IBinder> outBinder;
    EXPECT_EQ(INVALID_OPERATION,
              proc.rootIface->repeatBinder(someRealBinder, &outBinder).transactionError());
}

TEST(BinderRpc, CannotSendSocketBinderOverRegularBinder) {
    auto proc = createRpcTestSocketServerProcess(1);

    // for historical reasons, IServiceManager interface only returns the
    // exception code
    EXPECT_EQ(binder::Status::EX_TRANSACTION_FAILED,
              defaultServiceManager()->addService(String16("not_suspicious"), proc.rootBinder));
}

// END TESTS FOR LIMITATIONS OF SOCKET BINDER

TEST(BinderRpc, RepeatRootObject) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> outBinder;
    EXPECT_OK(proc.rootIface->repeatBinder(proc.rootBinder, &outBinder));
    EXPECT_EQ(proc.rootBinder, outBinder);
}

TEST(BinderRpc, NestedTransactions) {
    auto proc = createRpcTestSocketServerProcess(1);

    auto nastyNester = sp<MyBinderRpcTest>::make();
    EXPECT_OK(proc.rootIface->nestMe(nastyNester, 10));

    wp<IBinder> weak = nastyNester;
    nastyNester = nullptr;
    EXPECT_EQ(nullptr, weak.promote());
}

TEST(BinderRpc, SameBinderEquality) {
    auto proc = createRpcTestSocketServerProcess(1);

    sp<IBinder> a;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&a));

    sp<IBinder> b;
    EXPECT_OK(proc.rootIface->alwaysGiveMeTheSameBinder(&b));

    EXPECT_EQ(a, b);
}

TEST(BinderRpc, SameBinderEqualityWeak) {
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

TEST(BinderRpc, SingleSession) {
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

TEST(BinderRpc, ManySessions) {
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

TEST(BinderRpc, ThreadPoolGreaterThanEqualRequested) {
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

TEST(BinderRpc, ThreadPoolOverSaturated) {
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

TEST(BinderRpc, ThreadingStressTest) {
    constexpr size_t kNumClientThreads = 10;
    constexpr size_t kNumServerThreads = 10;
    constexpr size_t kNumCalls = 100;

    auto proc = createRpcTestSocketServerProcess(kNumServerThreads);

    std::vector<std::thread> threads;
    for (size_t i = 0; i < kNumClientThreads; i++) {
        threads.push_back(std::thread([&] {
            for (size_t j = 0; j < kNumCalls; j++) {
                sp<IBinder> out;
                proc.rootIface->repeatBinder(proc.rootBinder, &out);
                EXPECT_EQ(proc.rootBinder, out);
            }
        }));
    }

    for (auto& t : threads) t.join();
}

TEST(BinderRpc, OnewayCallDoesNotWait) {
    constexpr size_t kReallyLongTimeMs = 100;
    constexpr size_t kSleepMs = kReallyLongTimeMs * 5;

    // more than one thread, just so this doesn't deadlock
    auto proc = createRpcTestSocketServerProcess(2);

    size_t epochMsBefore = epochMillis();

    EXPECT_OK(proc.rootIface->sleepMsAsync(kSleepMs));

    size_t epochMsAfter = epochMillis();
    EXPECT_LT(epochMsAfter, epochMsBefore + kReallyLongTimeMs);
}

TEST(BinderRpc, OnewayCallQueueing) {
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

TEST(BinderRpc, Die) {
    // TODO(b/183141167): handle this in library
    signal(SIGPIPE, SIG_IGN);

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

        proc.proc.expectInvalid = true;
    }
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

TEST(BinderRpc, Fds) {
    ssize_t beforeFds = countFds();
    ASSERT_GE(beforeFds, 0);
    {
        auto proc = createRpcTestSocketServerProcess(10);
        ASSERT_EQ(OK, proc.rootBinder->pingBinder());
    }
    ASSERT_EQ(beforeFds, countFds()) << (system("ls -l /proc/self/fd/"), "fd leak?");
}

extern "C" int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    android::base::InitLogging(argv, android::base::StderrLogger, android::base::DefaultAborter);
    return RUN_ALL_TESTS();
}

} // namespace android
