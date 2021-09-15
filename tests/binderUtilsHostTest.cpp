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

#include <sysexits.h>

#include <chrono>

#include <android-base/result-gmock.h>
#include <android-base/strings.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../UtilsHost.h"

using android::base::testing::Ok;
using testing::Optional;

namespace android {

TEST(UtilsHost, ExecuteImmediately) {
    auto result = execute({"echo", "foo"}, nullptr);
    ASSERT_THAT(result, Ok());
    EXPECT_THAT(result->exitCode, Optional(EX_OK));
    EXPECT_EQ(result->stdoutStr, "foo\n");
}

TEST(UtilsHost, ExecuteLongRunning) {
    auto now = std::chrono::system_clock::now();

    {
        std::vector<std::string> args{"sh", "-c",
                                      "sleep 0.5 && echo -n f && sleep 0.5 && echo oo && sleep 1"};
        auto result = execute(std::move(args), [](const CommandResult& commandResult) {
            return android::base::EndsWith(commandResult.stdoutStr, "\n");
        });
        auto elapsed = std::chrono::system_clock::now() - now;
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        EXPECT_GE(elapsedMs, 1000);
        EXPECT_LT(elapsedMs, 2000);

        ASSERT_THAT(result, Ok());
        EXPECT_EQ(std::nullopt, result->exitCode);
        EXPECT_EQ(result->stdoutStr, "foo\n");
    }

    // ~CommandResult() called, child process is killed.
    // Assert that the second sleep does not finish.
    auto elapsed = std::chrono::system_clock::now() - now;
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    EXPECT_LT(elapsedMs, 2000);
}

TEST(UtilsHost, ExecuteLongRunning2) {
    auto now = std::chrono::system_clock::now();

    {
        std::vector<std::string> args{"sh", "-c",
                                      "sleep 2 && echo -n f && sleep 2 && echo oo && sleep 2"};
        auto result = execute(std::move(args), [](const CommandResult& commandResult) {
            return android::base::EndsWith(commandResult.stdoutStr, "\n");
        });
        auto elapsed = std::chrono::system_clock::now() - now;
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        EXPECT_GE(elapsedMs, 4000);
        EXPECT_LT(elapsedMs, 6000);

        ASSERT_THAT(result, Ok());
        EXPECT_EQ(std::nullopt, result->exitCode);
        EXPECT_EQ(result->stdoutStr, "foo\n");
    }

    // ~CommandResult() called, child process is killed.
    // Assert that the second sleep does not finish.
    auto elapsed = std::chrono::system_clock::now() - now;
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    EXPECT_LT(elapsedMs, 6000);
}

TEST(UtilsHost, KillWithSigKill) {
    std::vector<std::string> args{"sh", "-c", "echo foo && sleep 10"};
    auto result = execute(std::move(args), [](const CommandResult& commandResult) {
        // FOR TEST PURPOSE ONLY. DON'T DO THIS!
        if (commandResult.pid.has_value()) {
            (void)kill(*commandResult.pid, SIGKILL);
        }
        // FOR TEST PURPOSE ONLY. DON'T DO THIS!
        return false;
    });

    ASSERT_THAT(result, Ok());
    EXPECT_EQ(std::nullopt, result->exitCode);
    EXPECT_THAT(result->signal, Optional(SIGKILL));
}

} // namespace android
