/*
 * Copyright (C) 2021 The Android Open Source Project
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

// Integration test for servicedispatcher + adb forward. Requires ADB.

#include <stdlib.h>

#include <vector>

#include <android-base/parsebool.h>
#include <android-base/result-gmock.h>
#include <android-base/strings.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <binder/IServiceManager.h>
#include <binder/RpcSession.h>

#include "../UtilsHost.h"

using ::android::setDefaultServiceManager;
using ::android::base::EndsWith;
using ::android::base::Join;
using ::android::base::ParseBool;
using ::android::base::ParseBoolResult;
using ::android::base::Split;
using ::android::base::StartsWith;
using ::android::base::StringReplace;
using ::android::base::Trim;
using ::android::base::testing::Ok;
using ::std::chrono_literals::operator""ms;
using ::std::string_literals::operator""s;
using ::testing::AllOf;
using ::testing::Contains;
using ::testing::ContainsRegex;
using ::testing::ExplainMatchResult;
using ::testing::InitGoogleMock;

namespace android {

namespace {

constexpr const char* kServiceBinary = "/data/local/tmp/binderHostDeviceTest-service";
constexpr const char* kServiceName = "binderHostDeviceTestService";
constexpr const char* kDescriptor = "android.binderHostDeviceTestService";

// e.g. EXPECT_THAT(expr, StatusEq(OK)) << "additional message";
MATCHER_P(StatusEq, expected, (negation ? "not " : "") + statusToString(expected)) {
    *result_listener << statusToString(arg);
    return expected == arg;
}

void initHostRpcServiceManagerOnce() {
    static std::once_flag gSmOnce;
    std::call_once(gSmOnce, [] { setDefaultServiceManager(createRpcDelegateServiceManager()); });
}

// Test for host service manager.
class HostDeviceTest : public ::testing::Test {
public:
    void SetUp() override {
        auto debuggableResult = execute(Split("adb shell getprop ro.debuggable", " "), nullptr);
        ASSERT_THAT(debuggableResult, Ok());
        ASSERT_EQ(0, debuggableResult->exitCode) << *debuggableResult;
        auto debuggableBool = ParseBool(Trim(debuggableResult->stdout));
        ASSERT_NE(ParseBoolResult::kError, debuggableBool) << Trim(debuggableResult->stdout);
        if (debuggableBool == ParseBoolResult::kFalse) {
            GTEST_SKIP() << "ro.debuggable=" << Trim(debuggableResult->stdout);
        }

        auto lsResult = execute(Split("adb shell which servicedispatcher", " "), nullptr);
        ASSERT_THAT(lsResult, Ok());
        if (lsResult->exitCode != 0) {
            GTEST_SKIP() << "b/182914638: until feature is fully enabled, skip test on devices "
                            "without servicedispatcher";
        }

        initHostRpcServiceManagerOnce();
        ASSERT_NE(nullptr, defaultServiceManager()) << "No defaultServiceManager() over RPC";

        auto service = execute({"adb", "shell", kServiceBinary, kServiceName, kDescriptor},
                               &CommandResult::stdoutEndsWithNewLine);
        ASSERT_THAT(service, Ok());
        ASSERT_EQ(std::nullopt, service->exitCode) << *service;
        mService = std::move(*service);
    }
    void TearDown() override { mService.reset(); }

    [[nodiscard]] static sp<IBinder> get(unsigned int hostPort) {
        auto rpcSession = RpcSession::make();
        if (status_t status = rpcSession->setupInetClient("127.0.0.1", hostPort); status != OK) {
            ADD_FAILURE() << "Failed to setupInetClient on " << hostPort << ": "
                          << statusToString(status);
            return nullptr;
        }
        return rpcSession->getRootObject();
    }

private:
    std::optional<CommandResult> mService;
};

TEST_F(HostDeviceTest, List) {
    auto sm = defaultServiceManager();

    auto services = sm->listServices();
    ASSERT_THAT(services, Contains(String16(kServiceName)));
}

TEST_F(HostDeviceTest, CheckService) {
    auto sm = defaultServiceManager();

    auto rpcBinder = sm->checkService(String16(kServiceName));
    ASSERT_NE(nullptr, rpcBinder);

    EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
    EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
}

TEST_F(HostDeviceTest, GetService) {
    auto sm = defaultServiceManager();

    auto rpcBinder = sm->getService(String16(kServiceName));
    ASSERT_NE(nullptr, rpcBinder);

    EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
    EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
}

TEST_F(HostDeviceTest, WaitForService) {
    auto sm = defaultServiceManager();

    auto rpcBinder = sm->waitForService(String16(kServiceName));
    ASSERT_NE(nullptr, rpcBinder);

    EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
    EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
}

TEST_F(HostDeviceTest, TenClients) {
    auto sm = defaultServiceManager();

    auto threadFn = [&] {
        auto rpcBinder = sm->checkService(String16(kServiceName));
        ASSERT_NE(nullptr, rpcBinder);

        EXPECT_THAT(rpcBinder->pingBinder(), StatusEq(OK));
        EXPECT_EQ(String16(kDescriptor), rpcBinder->getInterfaceDescriptor());
    };

    std::vector<std::thread> threads;
    for (size_t i = 0; i < 10; ++i) threads.emplace_back(threadFn);
    for (auto& thread : threads) thread.join();
}

} // namespace

} // namespace android
