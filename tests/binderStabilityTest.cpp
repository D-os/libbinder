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

#include <android/os/IServiceManager.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>

#include "BnBinderStabilityTestSub.h"
#include "BnBinderStabilityTest.h"
#include "BpBinderStabilityTest.h"

using namespace android;
using android::binder::Status;
using android::os::IServiceManager;

const String16 kNoStabilityServer = String16("binder_stability_test_service_low");
const String16 kCompilationUnitServer = String16("binder_stability_test_service_compl");
const String16 kVintfServer = String16("binder_stability_test_service_vintf");

class BadStabilityTestSub : public BnBinderStabilityTestSub {
    Status userDefinedTransaction() {
        return Status::ok();
    }
};

sp<IBinderStabilityTestSub> getCompilationUnitStability() {
    sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
    // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
    // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
    internal::Stability::markCompilationUnit(iface.get()); // <- BAD, NO! DO NOT COPY
    return iface;
}

sp<IBinderStabilityTestSub> getVintfStability() {
    sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
    // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
    // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
    internal::Stability::markVintf(iface.get()); // <- BAD, NO! DO NOT COPY
    return iface;
}

sp<IBinderStabilityTestSub> getVendorStability() {
    sp<BnBinderStabilityTestSub> iface = new BadStabilityTestSub();
    // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
    // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
    internal::Stability::markVndk(iface.get()); // <- BAD, NO! DO NOT COPY
    return iface;
}

// NO! NO! NO! Do not even think of doing something like this!
// This is for testing! If a class like this was actually used in production,
// it would ruin everything!
class BadStabilityTester : public BnBinderStabilityTest {
public:
    Status sendBinder(const sp<IBinderStabilityTestSub>& /*binder*/) override {
        return Status::ok();
    }
    Status sendAndCallBinder(const sp<IBinderStabilityTestSub>& binder) override {
        return binder->userDefinedTransaction();
    }
    Status returnNoStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = new BadStabilityTestSub();
        return Status::ok();
    }
    Status returnLocalStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = getCompilationUnitStability();
        return Status::ok();
    }
    Status returnVintfStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = getVintfStability();
        return Status::ok();
    }
    Status returnVendorStabilityBinder(sp<IBinderStabilityTestSub>* _aidl_return) override {
        *_aidl_return = getVendorStability();
        return Status::ok();
    }
};

void checkSystemStabilityBinder(const sp<IBinderStabilityTest>& complServer) {
    EXPECT_TRUE(complServer->sendBinder(new BadStabilityTestSub()).isOk());
    EXPECT_TRUE(complServer->sendBinder(getCompilationUnitStability()).isOk());
    EXPECT_TRUE(complServer->sendBinder(getVintfStability()).isOk());
    EXPECT_TRUE(complServer->sendBinder(getVendorStability()).isOk());

    EXPECT_TRUE(complServer->sendAndCallBinder(new BadStabilityTestSub()).isOk());
    EXPECT_TRUE(complServer->sendAndCallBinder(getCompilationUnitStability()).isOk());
    EXPECT_TRUE(complServer->sendAndCallBinder(getVintfStability()).isOk());

    // !!! user-defined transaction may not be stable for remote server !!!
    EXPECT_FALSE(complServer->sendAndCallBinder(getVendorStability()).isOk());

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

class MarksStabilityInConstructor : public BBinder {
public:
    static bool gDestructed;

    MarksStabilityInConstructor() {
        internal::Stability::markCompilationUnit(this);
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
        internal::Stability::markCompilationUnit(compil.get());
        android::defaultServiceManager()->addService(kCompilationUnitServer, compil);

        sp<IBinder> vintf = new BadStabilityTester;
        internal::Stability::markVintf(vintf.get());
        android::defaultServiceManager()->addService(kVintfServer, vintf);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    // This is not racey. Just giving these services some time to register before we call
    // getService which sleeps for much longer...
    usleep(10000);

    return RUN_ALL_TESTS();
}
