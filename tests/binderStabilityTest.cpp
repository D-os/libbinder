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

#include "aidl/BnBinderStabilityTestSub.h"
#include "aidl/BnBinderStabilityTest.h"
#include "BnBinderStabilityTestSub.h"
#include "BnBinderStabilityTest.h"

using namespace android;
using namespace ndk;
using android::binder::Status;
using android::internal::Stability; // for testing only!

const String16 kNoStabilityServer = String16("binder_stability_test_service_low");
const String16 kCompilationUnitServer = String16("binder_stability_test_service_compl");
const String16 kVintfServer = String16("binder_stability_test_service_vintf");

const String16 kCompilationUnitNdkServer = String16("binder_stability_test_service_compl");

class BadStabilityTestSub : public BnBinderStabilityTestSub {
public:
    Status userDefinedTransaction() {
        return Status::ok();
    }

    static sp<IBinderStabilityTestSub> system() {
        sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
        // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
        // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
        Stability::markCompilationUnit(iface.get()); // <- BAD, NO! DO NOT COPY
        return iface;
    }

    static sp<IBinderStabilityTestSub> vintf() {
        sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
        // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
        // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
        Stability::markVintf(iface.get()); // <- BAD, NO! DO NOT COPY
        return iface;
    }

    static sp<IBinderStabilityTestSub> vendor() {
        sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
        // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
        // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
        Stability::markVndk(iface.get()); // <- BAD, NO! DO NOT COPY
        return iface;
    }
};

// NO! NO! NO! Do not even think of doing something like this!
// This is for testing! If a class like this was actually used in production,
// it would ruin everything!
class BadStabilityTester : public BnBinderStabilityTest {
public:
    Status sendBinder(const sp<IBinderStabilityTestSub>& /*binder*/) override {
        return Status::ok();
    }
    Status sendAndCallBinder(const sp<IBinderStabilityTestSub>& binder) override {
        Stability::debugLogStability("sendAndCallBinder got binder", IInterface::asBinder(binder));
        return binder->userDefinedTransaction();
    }
    Status returnNoStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = new BadStabilityTestSub();
        return Status::ok();
    }
    Status returnLocalStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = BadStabilityTestSub::system();
        return Status::ok();
    }
    Status returnVintfStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = BadStabilityTestSub::vintf();
        return Status::ok();
    }
    Status returnVendorStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = BadStabilityTestSub::vendor();
        return Status::ok();
    }
};

void checkSystemStabilityBinder(const sp<IBinderStabilityTest>& complServer) {
    EXPECT_TRUE(complServer->sendBinder(new BadStabilityTestSub()).isOk());
    EXPECT_TRUE(complServer->sendBinder(BadStabilityTestSub::system()).isOk());
    EXPECT_TRUE(complServer->sendBinder(BadStabilityTestSub::vintf()).isOk());
    EXPECT_TRUE(complServer->sendBinder(BadStabilityTestSub::vendor()).isOk());

    EXPECT_TRUE(complServer->sendAndCallBinder(new BadStabilityTestSub()).isOk());
    EXPECT_TRUE(complServer->sendAndCallBinder(BadStabilityTestSub::system()).isOk());
    EXPECT_TRUE(complServer->sendAndCallBinder(BadStabilityTestSub::vintf()).isOk());

    // !!! user-defined transaction may not be stable for remote server !!!
    EXPECT_FALSE(complServer->sendAndCallBinder(BadStabilityTestSub::vendor()).isOk());

    sp<IBinderStabilityTestSub> out;
    EXPECT_TRUE(complServer->returnNoStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, IInterface::asBinder(out)->pingBinder());
    EXPECT_TRUE(out->userDefinedTransaction().isOk());

    EXPECT_TRUE(complServer->returnLocalStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, IInterface::asBinder(out)->pingBinder());
    EXPECT_TRUE(out->userDefinedTransaction().isOk());

    EXPECT_TRUE(complServer->returnVintfStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());
    EXPECT_EQ(OK, IInterface::asBinder(out)->pingBinder());
    EXPECT_TRUE(out->userDefinedTransaction().isOk());

    EXPECT_TRUE(complServer->returnVendorStabilityBinder(&out).isOk());
    ASSERT_NE(nullptr, out.get());

    // !!! libbinder-defined transaction works !!!
    EXPECT_EQ(OK, IInterface::asBinder(out)->pingBinder());

    // !!! user-defined transaction may not be stable !!!
    EXPECT_FALSE(out->userDefinedTransaction().isOk());
}

TEST(BinderStability, RemoteNoStabilityServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kNoStabilityServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkSystemStabilityBinder(remoteServer);
}

TEST(BinderStability, RemoteLowStabilityServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kCompilationUnitServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkSystemStabilityBinder(remoteServer);
}

TEST(BinderStability, RemoteVintfServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kVintfServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkSystemStabilityBinder(remoteServer);
}

class NdkBadStabilityTestSub : public aidl::BnBinderStabilityTestSub {
    ScopedAStatus userDefinedTransaction() {
        return ScopedAStatus::ok();
    }
};
// for testing only to get around __ANDROID_VNDK__ guard.
extern "C" void AIBinder_markVendorStability(AIBinder* binder); // <- BAD DO NOT COPY

TEST(BinderStability, NdkClientOfRemoteServer) {
    SpAIBinder binder = SpAIBinder(AServiceManager_getService(
        String8(kCompilationUnitServer).c_str()));

    std::shared_ptr<aidl::IBinderStabilityTest> remoteServer =
        aidl::IBinderStabilityTest::fromBinder(binder);

    ASSERT_NE(nullptr, remoteServer.get());

    std::shared_ptr<aidl::IBinderStabilityTestSub> vendor = SharedRefBase::make<NdkBadStabilityTestSub>();

    // TODO: not ideal: binder must be held once it is marked
    SpAIBinder vendorBinder = vendor->asBinder();
    AIBinder_markVendorStability(vendorBinder.get());

    EXPECT_TRUE(remoteServer->sendBinder(vendor).isOk());
    EXPECT_FALSE(remoteServer->sendAndCallBinder(vendor).isOk());
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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        sp<IBinder> noStability = new BadStabilityTester;
        android::defaultServiceManager()->addService(kNoStabilityServer, noStability);

        sp<IBinder> compil = new BadStabilityTester;
        Stability::markCompilationUnit(compil.get());
        android::defaultServiceManager()->addService(kCompilationUnitServer, compil);

        sp<IBinder> vintf = new BadStabilityTester;
        Stability::markVintf(vintf.get());
        android::defaultServiceManager()->addService(kVintfServer, vintf);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    // This is not racey. Just giving these services some time to register before we call
    // getService which sleeps for much longer...
    usleep(10000);

    return RUN_ALL_TESTS();
}
