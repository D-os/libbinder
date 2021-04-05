/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android/binder_libbinder.h>
#include <android/binder_manager.h>
#include <android/binder_stability.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>

#include "aidl/BnBinderStabilityTest.h"
#include "BnBinderStabilityTest.h"

using namespace android;
using namespace ndk;
using android::binder::Status;
using android::internal::Stability; // for testing only!

const String16 kSystemStabilityServer = String16("binder_stability_test_service_system");

// This is handwritten so that we can test different stability levels w/o having the AIDL
// compiler assign them. Hand-writing binder interfaces is considered a bad practice
// sanity reasons. YOU SHOULD DEFINE AN AIDL INTERFACE INSTEAD!
class BadStableBinder : public BBinder {
public:
    static constexpr uint32_t USER_TRANSACTION = IBinder::FIRST_CALL_TRANSACTION;
    static String16 kDescriptor;

    bool gotUserTransaction = false;

    static status_t doUserTransaction(const sp<IBinder>& binder) {
        Parcel data, reply;
        data.writeInterfaceToken(kDescriptor);
        return binder->transact(USER_TRANSACTION, data, &reply, 0/*flags*/);
    }

    status_t onTransact(uint32_t code,
            const Parcel& data, Parcel* reply, uint32_t flags) override {
        if (code == USER_TRANSACTION) {
            // not interested in this kind of stability. Make sure
            // we have a test failure
            LOG_ALWAYS_FATAL_IF(!data.enforceInterface(kDescriptor));

            gotUserTransaction = true;

            ALOGE("binder stability: Got user transaction");
            return OK;
        }
        return BBinder::onTransact(code, data, reply, flags);
    }

    static sp<BadStableBinder> undef() {
        sp<BadStableBinder> iface = new BadStableBinder();
        return iface;
    }

    static sp<BadStableBinder> system() {
        sp<BadStableBinder> iface = new BadStableBinder();
        Stability::markCompilationUnit(iface.get()); // <- for test only
        return iface;
    }

    static sp<BadStableBinder> vintf() {
        sp<BadStableBinder> iface = new BadStableBinder();
        Stability::markVintf(iface.get()); // <- for test only
        return iface;
    }

    static sp<BadStableBinder> vendor() {
        sp<BadStableBinder> iface = new BadStableBinder();
        Stability::markVndk(iface.get()); // <- for test only
        return iface;
    }
};
String16 BadStableBinder::kDescriptor = String16("BadStableBinder.test");

// NO! NO! NO! Do not even think of doing something like this!
// This is for testing! If a class like this was actually used in production,
// it would ruin everything!
class MyBinderStabilityTest : public BnBinderStabilityTest {
public:
    Status sendBinder(const sp<IBinder>& /*binder*/) override {
        return Status::ok();
    }
    Status sendAndCallBinder(const sp<IBinder>& binder) override {
        Stability::debugLogStability("sendAndCallBinder got binder", binder);
        return Status::fromExceptionCode(BadStableBinder::doUserTransaction(binder));
    }
    Status returnNoStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = BadStableBinder::undef();
        return Status::ok();
    }
    Status returnLocalStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = BadStableBinder::system();
        return Status::ok();
    }
    Status returnVintfStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = BadStableBinder::vintf();
        return Status::ok();
    }
    Status returnVendorStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = BadStableBinder::vendor();
        return Status::ok();
    }
};

TEST(BinderStability, OnlyVintfStabilityBinderNeedsVintfDeclaration) {
    EXPECT_FALSE(Stability::requiresVintfDeclaration(nullptr));
    EXPECT_FALSE(Stability::requiresVintfDeclaration(BadStableBinder::undef()));
    EXPECT_FALSE(Stability::requiresVintfDeclaration(BadStableBinder::system()));
    EXPECT_FALSE(Stability::requiresVintfDeclaration(BadStableBinder::vendor()));

    EXPECT_TRUE(Stability::requiresVintfDeclaration(BadStableBinder::vintf()));
}

TEST(BinderStability, ForceDowngradeStability) {
    sp<IBinder> someBinder = BadStableBinder::vintf();

    EXPECT_TRUE(Stability::requiresVintfDeclaration(someBinder));

    // silly to do this after already using the binder, but it's for the test
    Stability::forceDowngradeToLocalStability(someBinder);

    EXPECT_FALSE(Stability::requiresVintfDeclaration(someBinder));
}

TEST(BinderStability, NdkForceDowngradeStability) {
    sp<IBinder> someBinder = BadStableBinder::vintf();

    EXPECT_TRUE(Stability::requiresVintfDeclaration(someBinder));

    // silly to do this after already using the binder, but it's for the test
    AIBinder_forceDowngradeToLocalStability(AIBinder_fromPlatformBinder(someBinder));

    EXPECT_FALSE(Stability::requiresVintfDeclaration(someBinder));
}

TEST(BinderStability, VintfStabilityServerMustBeDeclaredInManifest) {
    sp<IBinder> vintfServer = BadStableBinder::vintf();

    for (const char* instance8 : {
        ".", "/", "/.", "a.d.IFoo", "foo", "a.d.IFoo/foo"
    }) {
        String16 instance (instance8);

        EXPECT_EQ(Status::EX_ILLEGAL_ARGUMENT,
            android::defaultServiceManager()->addService(String16("."), vintfServer)) << instance8;
        EXPECT_FALSE(android::defaultServiceManager()->isDeclared(instance)) << instance8;
    }
}

TEST(BinderStability, CantCallVendorBinderInSystemContext) {
    sp<IBinder> serverBinder = android::defaultServiceManager()->getService(kSystemStabilityServer);
    auto server = interface_cast<IBinderStabilityTest>(serverBinder);

    ASSERT_NE(nullptr, server.get());
    ASSERT_NE(nullptr, IInterface::asBinder(server)->remoteBinder());

    EXPECT_TRUE(server->sendBinder(BadStableBinder::undef()).isOk());
    EXPECT_TRUE(server->sendBinder(BadStableBinder::system()).isOk());
    EXPECT_TRUE(server->sendBinder(BadStableBinder::vintf()).isOk());
    EXPECT_TRUE(server->sendBinder(BadStableBinder::vendor()).isOk());

    {
        sp<BadStableBinder> binder = BadStableBinder::undef();
        EXPECT_TRUE(server->sendAndCallBinder(binder).isOk());
        EXPECT_TRUE(binder->gotUserTransaction);
    }
    {
        sp<BadStableBinder> binder = BadStableBinder::system();
        EXPECT_TRUE(server->sendAndCallBinder(binder).isOk());
        EXPECT_TRUE(binder->gotUserTransaction);
    }
    {
        sp<BadStableBinder> binder = BadStableBinder::vintf();
        EXPECT_TRUE(server->sendAndCallBinder(binder).isOk());
        EXPECT_TRUE(binder->gotUserTransaction);
    }
    {
        // !!! user-defined transaction may not be stable for remote server !!!
        // !!! so, it does not work !!!
        sp<BadStableBinder> binder = BadStableBinder::vendor();
        EXPECT_EQ(BAD_TYPE, server->sendAndCallBinder(binder).exceptionCode());
        EXPECT_FALSE(binder->gotUserTransaction);
    }

    sp<IBinder> out;
    EXPECT_TRUE(server->returnNoStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, out->pingBinder());
    EXPECT_EQ(OK, BadStableBinder::doUserTransaction(out));

    EXPECT_TRUE(server->returnLocalStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, out->pingBinder());
    EXPECT_EQ(OK, BadStableBinder::doUserTransaction(out));

    EXPECT_TRUE(server->returnVintfStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, out->pingBinder());
    EXPECT_EQ(OK, BadStableBinder::doUserTransaction(out));

    EXPECT_TRUE(server->returnVendorStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());

    // !!! libbinder-defined transaction works !!!
    EXPECT_EQ(OK, out->pingBinder());

    // !!! user-defined transaction may not be stable !!!
    // !!! so, it does not work !!!
    EXPECT_EQ(BAD_TYPE, BadStableBinder::doUserTransaction(out));
}

// This is handwritten so that we can test different stability levels w/o having the AIDL
// compiler assign them. Hand-writing binder interfaces is considered a bad practice
// sanity reasons. YOU SHOULD DEFINE AN AIDL INTERFACE INSTEAD!

struct NdkBinderStable_DataClass {
    bool gotUserTransaction = false;
};
void* NdkBadStableBinder_Class_onCreate(void* args) {
    LOG_ALWAYS_FATAL_IF(args != nullptr, "Takes no args");
    return static_cast<void*>(new NdkBinderStable_DataClass);
}
void NdkBadStableBinder_Class_onDestroy(void* userData) {
    delete static_cast<NdkBinderStable_DataClass*>(userData);
}
NdkBinderStable_DataClass* NdkBadStableBinder_getUserData(AIBinder* binder) {
    LOG_ALWAYS_FATAL_IF(binder == nullptr);
    void* userData = AIBinder_getUserData(binder);
    LOG_ALWAYS_FATAL_IF(userData == nullptr, "null data - binder is remote?");

    return static_cast<NdkBinderStable_DataClass*>(userData);
}
binder_status_t NdkBadStableBinder_Class_onTransact(
    AIBinder* binder, transaction_code_t code, const AParcel* /*in*/, AParcel* /*out*/) {

    if (code == BadStableBinder::USER_TRANSACTION) {
        ALOGE("ndk binder stability: Got user transaction");
        NdkBadStableBinder_getUserData(binder)->gotUserTransaction = true;
        return STATUS_OK;
    }

    return STATUS_UNKNOWN_TRANSACTION;
}

static AIBinder_Class* kNdkBadStableBinder =
    AIBinder_Class_define(String8(BadStableBinder::kDescriptor).c_str(),
                          NdkBadStableBinder_Class_onCreate,
                          NdkBadStableBinder_Class_onDestroy,
                          NdkBadStableBinder_Class_onTransact);

// for testing only to get around __ANDROID_VNDK__ guard.
extern "C" void AIBinder_markVendorStability(AIBinder* binder); // <- BAD DO NOT COPY

TEST(BinderStability, NdkCantCallVendorBinderInSystemContext) {
    SpAIBinder binder = SpAIBinder(AServiceManager_getService(
        String8(kSystemStabilityServer).c_str()));

    std::shared_ptr<aidl::IBinderStabilityTest> remoteServer =
        aidl::IBinderStabilityTest::fromBinder(binder);

    ASSERT_NE(nullptr, remoteServer.get());

    SpAIBinder comp = SpAIBinder(AIBinder_new(kNdkBadStableBinder, nullptr /*args*/));
    EXPECT_TRUE(remoteServer->sendBinder(comp).isOk());
    EXPECT_TRUE(remoteServer->sendAndCallBinder(comp).isOk());
    EXPECT_TRUE(NdkBadStableBinder_getUserData(comp.get())->gotUserTransaction);

    SpAIBinder vendor = SpAIBinder(AIBinder_new(kNdkBadStableBinder, nullptr /*args*/));
    AIBinder_markVendorStability(vendor.get());
    EXPECT_TRUE(remoteServer->sendBinder(vendor).isOk());
    EXPECT_FALSE(remoteServer->sendAndCallBinder(vendor).isOk());
    EXPECT_FALSE(NdkBadStableBinder_getUserData(vendor.get())->gotUserTransaction);
}

class MarksStabilityInConstructor : public BBinder {
public:
    static bool gDestructed;

    MarksStabilityInConstructor() {
        Stability::markCompilationUnit(this);
    }
    ~MarksStabilityInConstructor() {
        gDestructed = true;
    }
};
bool MarksStabilityInConstructor::gDestructed = false;

TEST(BinderStability, MarkingObjectNoDestructTest) {
    ASSERT_FALSE(MarksStabilityInConstructor::gDestructed);

    // best practice is to put this directly in an sp, but for this test, we
    // want to explicitly check what happens before that happens
    MarksStabilityInConstructor* binder = new MarksStabilityInConstructor();
    ASSERT_FALSE(MarksStabilityInConstructor::gDestructed);

    sp<MarksStabilityInConstructor> binderSp = binder;
    ASSERT_FALSE(MarksStabilityInConstructor::gDestructed);

    binderSp = nullptr;
    ASSERT_TRUE(MarksStabilityInConstructor::gDestructed);
}

TEST(BinderStability, RemarkDies) {
    ASSERT_DEATH({
        sp<IBinder> binder = new BBinder();
        Stability::markCompilationUnit(binder.get()); // <-- only called for tests
        Stability::markVndk(binder.get()); // <-- only called for tests
    }, "Should only mark known object.");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        sp<IBinder> server = new MyBinderStabilityTest;
        android::defaultServiceManager()->addService(kSystemStabilityServer, server);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    // This is not racey. Just giving these services some time to register before we call
    // getService which sleeps for much longer...
    usleep(10000);

    return RUN_ALL_TESTS();
}
