/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <IBinderNdkUnitTest.h>
#include <aidl/BnBinderNdkUnitTest.h>
#include <aidl/BnEmpty.h>
#include <android-base/logging.h>
#include <android/binder_ibinder_jni.h>
#include <android/binder_ibinder_platform.h>
#include <android/binder_libbinder.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <iface/iface.h>
#include <utils/Looper.h>

// warning: this is assuming that libbinder_ndk is using the same copy
// of libbinder that we are.
#include <binder/IPCThreadState.h>
#include <binder/IResultReceiver.h>
#include <binder/IServiceManager.h>
#include <binder/IShellCallback.h>

#include <sys/prctl.h>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include "android/binder_ibinder.h"

using namespace android;

constexpr char kExistingNonNdkService[] = "SurfaceFlinger";
constexpr char kBinderNdkUnitTestService[] = "BinderNdkUnitTest";
constexpr char kLazyBinderNdkUnitTestService[] = "LazyBinderNdkUnitTest";

class MyBinderNdkUnitTest : public aidl::BnBinderNdkUnitTest {
    ndk::ScopedAStatus repeatInt(int32_t in, int32_t* out) {
        *out = in;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus takeInterface(const std::shared_ptr<aidl::IEmpty>& empty) {
        (void)empty;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus forceFlushCommands() {
        // warning: this is assuming that libbinder_ndk is using the same copy
        // of libbinder that we are.
        android::IPCThreadState::self()->flushCommands();
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getsRequestedSid(bool* out) {
        const char* sid = AIBinder_getCallingSid();
        std::cout << "Got security context: " << (sid ?: "null") << std::endl;
        *out = sid != nullptr;
        return ndk::ScopedAStatus::ok();
    }
    binder_status_t handleShellCommand(int /*in*/, int out, int /*err*/, const char** args,
                                       uint32_t numArgs) override {
        for (uint32_t i = 0; i < numArgs; i++) {
            dprintf(out, "%s", args[i]);
        }
        fsync(out);
        return STATUS_OK;
    }
};

int generatedService() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto service = ndk::SharedRefBase::make<MyBinderNdkUnitTest>();
    auto binder = service->asBinder();

    AIBinder_setRequestingSid(binder.get(), true);

    binder_exception_t exception =
            AServiceManager_addService(binder.get(), kBinderNdkUnitTestService);

    if (exception != EX_NONE) {
        LOG(FATAL) << "Could not register: " << exception << " " << kBinderNdkUnitTestService;
    }

    ABinderProcess_joinThreadPool();

    return 1;  // should not return
}

// manually-written parceling class considered bad practice
class MyFoo : public IFoo {
    binder_status_t doubleNumber(int32_t in, int32_t* out) override {
        *out = 2 * in;
        LOG(INFO) << "doubleNumber (" << in << ") => " << *out;
        return STATUS_OK;
    }

    binder_status_t die() override {
        LOG(FATAL) << "IFoo::die called!";
        return STATUS_UNKNOWN_ERROR;
    }
};

void manualService(const char* instance) {
    // Strong reference to MyFoo kept by service manager.
    binder_exception_t exception = (new MyFoo)->addService(instance);

    if (exception != EX_NONE) {
        LOG(FATAL) << "Could not register: " << exception << " " << instance;
    }
}
int manualPollingService(const char* instance) {
    int fd;
    CHECK(STATUS_OK == ABinderProcess_setupPolling(&fd));
    manualService(instance);

    class Handler : public LooperCallback {
        int handleEvent(int /*fd*/, int /*events*/, void* /*data*/) override {
            ABinderProcess_handlePolledCommands();
            return 1;  // Continue receiving callbacks.
        }
    };

    sp<Looper> looper = Looper::prepare(0 /* opts */);
    looper->addFd(fd, Looper::POLL_CALLBACK, Looper::EVENT_INPUT, new Handler(), nullptr /*data*/);
    // normally, would add additional fds
    while (true) {
        looper->pollAll(-1 /* timeoutMillis */);
    }
    return 1;  // should not reach
}
int manualThreadPoolService(const char* instance) {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    manualService(instance);
    ABinderProcess_joinThreadPool();
    return 1;
}

int lazyService(const char* instance) {
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Wait to register this service to make sure the main test process will
    // actually wait for the service to be available. Tested with sleep(60),
    // and reduced for sake of time.
    sleep(1);
    // Strong reference to MyBinderNdkUnitTest kept by service manager.
    // This is just for testing, it has no corresponding init behavior.
    auto service = ndk::SharedRefBase::make<MyBinderNdkUnitTest>();
    auto binder = service->asBinder();

    binder_status_t status = AServiceManager_registerLazyService(binder.get(), instance);
    if (status != STATUS_OK) {
        LOG(FATAL) << "Could not register: " << status << " " << instance;
    }

    ABinderProcess_joinThreadPool();

    return 1;  // should not return
}

TEST(NdkBinder, GetServiceThatDoesntExist) {
    sp<IFoo> foo = IFoo::getService("asdfghkl;");
    EXPECT_EQ(nullptr, foo.get());
}

TEST(NdkBinder, CheckServiceThatDoesntExist) {
    AIBinder* binder = AServiceManager_checkService("asdfghkl;");
    ASSERT_EQ(nullptr, binder);
}

TEST(NdkBinder, CheckServiceThatDoesExist) {
    AIBinder* binder = AServiceManager_checkService(kExistingNonNdkService);
    EXPECT_NE(nullptr, binder);
    EXPECT_EQ(STATUS_OK, AIBinder_ping(binder));

    AIBinder_decStrong(binder);
}

TEST(NdkBinder, UnimplementedDump) {
    sp<IFoo> foo = IFoo::getService(IFoo::kSomeInstanceName);
    ASSERT_NE(foo, nullptr);
    AIBinder* binder = foo->getBinder();
    EXPECT_EQ(OK, AIBinder_dump(binder, STDOUT_FILENO, nullptr, 0));
    AIBinder_decStrong(binder);
}

TEST(NdkBinder, UnimplementedShell) {
    // libbinder_ndk doesn't support calling shell, so we are calling from the
    // libbinder across processes to the NDK service which doesn't implement
    // shell
    static const sp<android::IServiceManager> sm(android::defaultServiceManager());
    sp<IBinder> testService = sm->getService(String16(IFoo::kSomeInstanceName));

    Vector<String16> argsVec;
    EXPECT_EQ(OK, IBinder::shellCommand(testService, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                                        argsVec, nullptr, nullptr));
}

TEST(NdkBinder, DoubleNumber) {
    sp<IFoo> foo = IFoo::getService(IFoo::kSomeInstanceName);
    ASSERT_NE(foo, nullptr);

    int32_t out;
    EXPECT_EQ(STATUS_OK, foo->doubleNumber(1, &out));
    EXPECT_EQ(2, out);
}

TEST(NdkBinder, GetLazyService) {
    // Not declared in the vintf manifest
    ASSERT_FALSE(AServiceManager_isDeclared(kLazyBinderNdkUnitTestService));
    ndk::SpAIBinder binder(AServiceManager_waitForService(kLazyBinderNdkUnitTestService));
    std::shared_ptr<aidl::IBinderNdkUnitTest> service =
            aidl::IBinderNdkUnitTest::fromBinder(binder);
    ASSERT_NE(service, nullptr);

    EXPECT_EQ(STATUS_OK, AIBinder_ping(binder.get()));
}

// This is too slow
TEST(NdkBinder, CheckLazyServiceShutDown) {
    ndk::SpAIBinder binder(AServiceManager_waitForService(kLazyBinderNdkUnitTestService));
    std::shared_ptr<aidl::IBinderNdkUnitTest> service =
            aidl::IBinderNdkUnitTest::fromBinder(binder);
    ASSERT_NE(service, nullptr);

    EXPECT_EQ(STATUS_OK, AIBinder_ping(binder.get()));
    binder = nullptr;
    service = nullptr;
    IPCThreadState::self()->flushCommands();
    // Make sure the service is dead after some time of no use
    sleep(10);
    ASSERT_EQ(nullptr, AServiceManager_checkService(kLazyBinderNdkUnitTestService));
}

void LambdaOnDeath(void* cookie) {
    auto onDeath = static_cast<std::function<void(void)>*>(cookie);
    (*onDeath)();
};
TEST(NdkBinder, DeathRecipient) {
    using namespace std::chrono_literals;

    AIBinder* binder;
    sp<IFoo> foo = IFoo::getService(IFoo::kInstanceNameToDieFor, &binder);
    ASSERT_NE(nullptr, foo.get());
    ASSERT_NE(nullptr, binder);

    std::mutex deathMutex;
    std::condition_variable deathCv;
    bool deathRecieved = false;

    std::function<void(void)> onDeath = [&] {
        std::cerr << "Binder died (as requested)." << std::endl;
        deathRecieved = true;
        deathCv.notify_one();
    };

    AIBinder_DeathRecipient* recipient = AIBinder_DeathRecipient_new(LambdaOnDeath);

    EXPECT_EQ(STATUS_OK, AIBinder_linkToDeath(binder, recipient, static_cast<void*>(&onDeath)));

    // the binder driver should return this if the service dies during the transaction
    EXPECT_EQ(STATUS_DEAD_OBJECT, foo->die());

    foo = nullptr;

    std::unique_lock<std::mutex> lock(deathMutex);
    EXPECT_TRUE(deathCv.wait_for(lock, 1s, [&] { return deathRecieved; }));
    EXPECT_TRUE(deathRecieved);

    AIBinder_DeathRecipient_delete(recipient);
    AIBinder_decStrong(binder);
    binder = nullptr;
}

TEST(NdkBinder, RetrieveNonNdkService) {
    AIBinder* binder = AServiceManager_getService(kExistingNonNdkService);
    ASSERT_NE(nullptr, binder);
    EXPECT_TRUE(AIBinder_isRemote(binder));
    EXPECT_TRUE(AIBinder_isAlive(binder));
    EXPECT_EQ(STATUS_OK, AIBinder_ping(binder));

    AIBinder_decStrong(binder);
}

void OnBinderDeath(void* cookie) {
    LOG(ERROR) << "BINDER DIED. COOKIE: " << cookie;
}

TEST(NdkBinder, LinkToDeath) {
    AIBinder* binder = AServiceManager_getService(kExistingNonNdkService);
    ASSERT_NE(nullptr, binder);

    AIBinder_DeathRecipient* recipient = AIBinder_DeathRecipient_new(OnBinderDeath);
    ASSERT_NE(nullptr, recipient);

    EXPECT_EQ(STATUS_OK, AIBinder_linkToDeath(binder, recipient, nullptr));
    EXPECT_EQ(STATUS_OK, AIBinder_linkToDeath(binder, recipient, nullptr));
    EXPECT_EQ(STATUS_OK, AIBinder_unlinkToDeath(binder, recipient, nullptr));
    EXPECT_EQ(STATUS_OK, AIBinder_unlinkToDeath(binder, recipient, nullptr));
    EXPECT_EQ(STATUS_NAME_NOT_FOUND, AIBinder_unlinkToDeath(binder, recipient, nullptr));

    AIBinder_DeathRecipient_delete(recipient);
    AIBinder_decStrong(binder);
}

class MyTestFoo : public IFoo {
    binder_status_t doubleNumber(int32_t in, int32_t* out) override {
        *out = 2 * in;
        LOG(INFO) << "doubleNumber (" << in << ") => " << *out;
        return STATUS_OK;
    }
    binder_status_t die() override {
        ADD_FAILURE() << "die called on local instance";
        return STATUS_OK;
    }
};

TEST(NdkBinder, AddNullService) {
    EXPECT_EQ(EX_ILLEGAL_ARGUMENT, AServiceManager_addService(nullptr, "any-service-name"));
}

TEST(NdkBinder, AddInvalidServiceName) {
    sp<IFoo> foo = new MyTestFoo;
    EXPECT_EQ(EX_ILLEGAL_ARGUMENT, foo->addService("!@#$%^&"));
}

TEST(NdkBinder, GetServiceInProcess) {
    static const char* kInstanceName = "test-get-service-in-process";

    sp<IFoo> foo = new MyTestFoo;
    EXPECT_EQ(EX_NONE, foo->addService(kInstanceName));

    sp<IFoo> getFoo = IFoo::getService(kInstanceName);
    EXPECT_EQ(foo.get(), getFoo.get());

    int32_t out;
    EXPECT_EQ(STATUS_OK, getFoo->doubleNumber(1, &out));
    EXPECT_EQ(2, out);
}

TEST(NdkBinder, EqualityOfRemoteBinderPointer) {
    AIBinder* binderA = AServiceManager_getService(kExistingNonNdkService);
    ASSERT_NE(nullptr, binderA);

    AIBinder* binderB = AServiceManager_getService(kExistingNonNdkService);
    ASSERT_NE(nullptr, binderB);

    EXPECT_EQ(binderA, binderB);

    AIBinder_decStrong(binderA);
    AIBinder_decStrong(binderB);
}

TEST(NdkBinder, ToFromJavaNullptr) {
    EXPECT_EQ(nullptr, AIBinder_toJavaBinder(nullptr, nullptr));
    EXPECT_EQ(nullptr, AIBinder_fromJavaBinder(nullptr, nullptr));
}

TEST(NdkBinder, ABpBinderRefCount) {
    AIBinder* binder = AServiceManager_getService(kExistingNonNdkService);
    AIBinder_Weak* wBinder = AIBinder_Weak_new(binder);

    ASSERT_NE(nullptr, binder);
    EXPECT_EQ(1, AIBinder_debugGetRefCount(binder));

    AIBinder_decStrong(binder);

    ASSERT_EQ(nullptr, AIBinder_Weak_promote(wBinder));

    AIBinder_Weak_delete(wBinder);
}

TEST(NdkBinder, AddServiceMultipleTimes) {
    static const char* kInstanceName1 = "test-multi-1";
    static const char* kInstanceName2 = "test-multi-2";
    sp<IFoo> foo = new MyTestFoo;
    EXPECT_EQ(EX_NONE, foo->addService(kInstanceName1));
    EXPECT_EQ(EX_NONE, foo->addService(kInstanceName2));
    EXPECT_EQ(IFoo::getService(kInstanceName1), IFoo::getService(kInstanceName2));
}

TEST(NdkBinder, RequestedSidWorks) {
    ndk::SpAIBinder binder(AServiceManager_getService(kBinderNdkUnitTestService));
    std::shared_ptr<aidl::IBinderNdkUnitTest> service =
            aidl::IBinderNdkUnitTest::fromBinder(binder);

    bool gotSid = false;
    EXPECT_TRUE(service->getsRequestedSid(&gotSid).isOk());
    EXPECT_TRUE(gotSid);
}

TEST(NdkBinder, SentAidlBinderCanBeDestroyed) {
    static volatile bool destroyed = false;
    static std::mutex dMutex;
    static std::condition_variable cv;

    class MyEmpty : public aidl::BnEmpty {
        virtual ~MyEmpty() {
            destroyed = true;
            cv.notify_one();
        }
    };

    std::shared_ptr<MyEmpty> empty = ndk::SharedRefBase::make<MyEmpty>();

    ndk::SpAIBinder binder(AServiceManager_getService(kBinderNdkUnitTestService));
    std::shared_ptr<aidl::IBinderNdkUnitTest> service =
            aidl::IBinderNdkUnitTest::fromBinder(binder);

    EXPECT_FALSE(destroyed);

    service->takeInterface(empty);
    service->forceFlushCommands();
    empty = nullptr;

    // give other binder thread time to process commands
    {
        using namespace std::chrono_literals;
        std::unique_lock<std::mutex> lk(dMutex);
        cv.wait_for(lk, 1s, [] { return destroyed; });
    }

    EXPECT_TRUE(destroyed);
}

TEST(NdkBinder, ConvertToPlatformBinder) {
    for (const ndk::SpAIBinder& binder :
         {// remote
          ndk::SpAIBinder(AServiceManager_getService(kBinderNdkUnitTestService)),
          // local
          ndk::SharedRefBase::make<MyBinderNdkUnitTest>()->asBinder()}) {
        // convert to platform binder
        EXPECT_NE(binder.get(), nullptr);
        sp<IBinder> platformBinder = AIBinder_toPlatformBinder(binder.get());
        EXPECT_NE(platformBinder.get(), nullptr);
        auto proxy = interface_cast<IBinderNdkUnitTest>(platformBinder);
        EXPECT_NE(proxy, nullptr);

        // use platform binder
        int out;
        EXPECT_TRUE(proxy->repeatInt(4, &out).isOk());
        EXPECT_EQ(out, 4);

        // convert back
        ndk::SpAIBinder backBinder = ndk::SpAIBinder(AIBinder_fromPlatformBinder(platformBinder));
        EXPECT_EQ(backBinder.get(), binder.get());
    }
}

class MyResultReceiver : public BnResultReceiver {
   public:
    Mutex mMutex;
    Condition mCondition;
    bool mHaveResult = false;
    int32_t mResult = 0;

    virtual void send(int32_t resultCode) {
        AutoMutex _l(mMutex);
        mResult = resultCode;
        mHaveResult = true;
        mCondition.signal();
    }

    int32_t waitForResult() {
        AutoMutex _l(mMutex);
        while (!mHaveResult) {
            mCondition.wait(mMutex);
        }
        return mResult;
    }
};

class MyShellCallback : public BnShellCallback {
   public:
    virtual int openFile(const String16& /*path*/, const String16& /*seLinuxContext*/,
                         const String16& /*mode*/) {
        // Empty implementation.
        return 0;
    }
};

bool ReadFdToString(int fd, std::string* content) {
    char buf[64];
    ssize_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], sizeof(buf)))) > 0) {
        content->append(buf, n);
    }
    return (n == 0) ? true : false;
}

std::string shellCmdToString(sp<IBinder> unitTestService, const std::vector<const char*>& args) {
    int inFd[2] = {-1, -1};
    int outFd[2] = {-1, -1};
    int errFd[2] = {-1, -1};

    EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, inFd));
    EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, outFd));
    EXPECT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, errFd));

    sp<MyShellCallback> cb = new MyShellCallback();
    sp<MyResultReceiver> resultReceiver = new MyResultReceiver();

    Vector<String16> argsVec;
    for (int i = 0; i < args.size(); i++) {
        argsVec.add(String16(args[i]));
    }
    status_t error = IBinder::shellCommand(unitTestService, inFd[0], outFd[0], errFd[0], argsVec,
                                           cb, resultReceiver);
    EXPECT_EQ(error, android::OK);

    status_t res = resultReceiver->waitForResult();
    EXPECT_EQ(res, android::OK);

    close(inFd[0]);
    close(inFd[1]);
    close(outFd[0]);
    close(errFd[0]);
    close(errFd[1]);

    std::string ret;
    EXPECT_TRUE(ReadFdToString(outFd[1], &ret));
    close(outFd[1]);
    return ret;
}

TEST(NdkBinder, UseHandleShellCommand) {
    static const sp<android::IServiceManager> sm(android::defaultServiceManager());
    sp<IBinder> testService = sm->getService(String16(kBinderNdkUnitTestService));

    EXPECT_EQ("", shellCmdToString(testService, {}));
    EXPECT_EQ("", shellCmdToString(testService, {"", ""}));
    EXPECT_EQ("Hello world!", shellCmdToString(testService, {"Hello ", "world!"}));
    EXPECT_EQ("CMD", shellCmdToString(testService, {"C", "M", "D"}));
}

TEST(NdkBinder, GetClassInterfaceDescriptor) {
    ASSERT_STREQ(IFoo::kIFooDescriptor, AIBinder_Class_getDescriptor(IFoo::kClass));
}

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return manualThreadPoolService(IFoo::kInstanceNameToDieFor);
    }
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return manualPollingService(IFoo::kSomeInstanceName);
    }
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return lazyService(kLazyBinderNdkUnitTestService);
    }
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        return generatedService();
    }

    ABinderProcess_setThreadPoolMaxThreadCount(1);  // to recieve death notifications/callbacks
    ABinderProcess_startThreadPool();

    return RUN_ALL_TESTS();
}

#include <android/binder_auto_utils.h>
#include <android/binder_interface_utils.h>
#include <android/binder_parcel_utils.h>
