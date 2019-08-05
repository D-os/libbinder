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

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>

#include "BnBinderStabilityTest.h"
#include "BpBinderStabilityTest.h"

using namespace android;
using android::binder::Status;

const String16 kNoStabilityServer = String16("binder_stability_test_service_low");
const String16 kCompilationUnitServer = String16("binder_stability_test_service_compl");
const String16 kVintfServer = String16("binder_stability_test_service_vintf");

sp<IBinder> getCompilationUnitStability() {
    sp<IBinder> binder = new BBinder();
    // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
    // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
    internal::Stability::markCompilationUnit(binder.get()); // <- BAD, NO! DO NOT COPY
    return binder;
}

sp<IBinder> getVintfStability() {
    sp<IBinder> binder = new BBinder();
    // NO! NO! NO! NO! DO NOT EVERY DO SOMETHING LIKE THIS?
    // WHAT ARE YOU CRAZY? IT'S VERY DANGEROUS
    internal::Stability::markVintf(binder.get()); // <- BAD, NO! DO NOT COPY
    return binder;
}

// NO! NO! NO! Do not even think of doing something like this!
// This is for testing! If a class like this was actually used in production,
// it would ruin everything!
class BadStabilityTester : public BnBinderStabilityTest {
public:
    Status sendBinder(const sp<IBinder>& /*binder*/) override {
        return Status::ok();
    }
    Status returnNoStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = new BBinder();
        return Status::ok();
    }
    Status returnLocalStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = getCompilationUnitStability();
        return Status::ok();
    }
    Status returnVintfStabilityBinder(sp<IBinder>* _aidl_return) override {
        *_aidl_return = getVintfStability();
        return Status::ok();
    }

    static sp<IBinderStabilityTest> getNoStabilityServer() {
        sp<IBinder> remote = new BadStabilityTester;
        return new BpBinderStabilityTest(remote);
    }
    static sp<IBinderStabilityTest> getCompilationUnitStabilityServer() {
        sp<IBinder> remote = new BadStabilityTester;
        internal::Stability::markCompilationUnit(remote.get());
        return new BpBinderStabilityTest(remote);
    }
    static sp<IBinderStabilityTest> getVintfStabilityServer() {
        sp<IBinder> remote = new BadStabilityTester;
        internal::Stability::markVintf(remote.get()); // <- BAD, NO! DO NOT COPY
        return new BpBinderStabilityTest(remote);
    }
};

void checkNoStabilityServer(const sp<IBinderStabilityTest>& unkemptServer) {
    EXPECT_TRUE(unkemptServer->sendBinder(new BBinder()).isOk());
    EXPECT_TRUE(unkemptServer->sendBinder(getCompilationUnitStability()).isOk());
    EXPECT_TRUE(unkemptServer->sendBinder(getVintfStability()).isOk());

    sp<IBinder> out;
    EXPECT_TRUE(unkemptServer->returnNoStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());

    EXPECT_TRUE(unkemptServer->returnLocalStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());

    EXPECT_TRUE(unkemptServer->returnVintfStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());
}

void checkLowStabilityServer(const sp<IBinderStabilityTest>& complServer) {
    EXPECT_FALSE(complServer->sendBinder(new BBinder()).isOk());
    EXPECT_TRUE(complServer->sendBinder(getCompilationUnitStability()).isOk());
    EXPECT_TRUE(complServer->sendBinder(getVintfStability()).isOk());

    sp<IBinder> out;
    EXPECT_FALSE(complServer->returnNoStabilityBinder(&out).isOk());
    EXPECT_EQ(nullptr, out.get());

    EXPECT_TRUE(complServer->returnLocalStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());

    EXPECT_TRUE(complServer->returnVintfStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());
}

void checkHighStabilityServer(const sp<IBinderStabilityTest>& highStability) {
    EXPECT_FALSE(highStability->sendBinder(new BBinder()).isOk());
    EXPECT_FALSE(highStability->sendBinder(getCompilationUnitStability()).isOk());
    EXPECT_TRUE(highStability->sendBinder(getVintfStability()).isOk());

    sp<IBinder> out;
    EXPECT_FALSE(highStability->returnNoStabilityBinder(&out).isOk());
    EXPECT_EQ(nullptr, out.get());

    EXPECT_FALSE(highStability->returnLocalStabilityBinder(&out).isOk());
    EXPECT_EQ(nullptr, out.get());

    EXPECT_TRUE(highStability->returnVintfStabilityBinder(&out).isOk());
    EXPECT_NE(nullptr, out.get());
}

TEST(BinderStability, LocalNoStabilityServer) {
    // in practice, a low stability server is probably one that hasn't been rebuilt
    // or was written by hand.
    auto server = BadStabilityTester::getNoStabilityServer();
    ASSERT_NE(nullptr, IInterface::asBinder(server)->localBinder());
    checkNoStabilityServer(server);
}

TEST(BinderStability, LocalLowStabilityServer) {
    auto server = BadStabilityTester::getCompilationUnitStabilityServer();
    ASSERT_NE(nullptr, IInterface::asBinder(server)->localBinder());
    checkLowStabilityServer(server);
}

TEST(BinderStability, LocalHighStabilityServer) {
    auto server = BadStabilityTester::getVintfStabilityServer();
    ASSERT_NE(nullptr, IInterface::asBinder(server)->localBinder());
    checkHighStabilityServer(server);
}

TEST(BinderStability, RemoteNoStabilityServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kNoStabilityServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkNoStabilityServer(remoteServer);
}

TEST(BinderStability, RemoteLowStabilityServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kCompilationUnitServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkLowStabilityServer(remoteServer);
}

TEST(BinderStability, RemoteVintfServer) {
    sp<IBinder> remoteBinder = android::defaultServiceManager()->getService(kVintfServer);
    auto remoteServer = interface_cast<IBinderStabilityTest>(remoteBinder);

    ASSERT_NE(nullptr, remoteServer.get());
    ASSERT_NE(nullptr, IInterface::asBinder(remoteServer)->remoteBinder());

    checkHighStabilityServer(remoteServer);
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
