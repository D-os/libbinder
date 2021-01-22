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

#include <android-base/logging.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <gtest/gtest.h>

#include <sys/prctl.h>
#include <thread>

using namespace android;

const String16 kServerName = String16("binderClearBuf");

std::string hexString(const void* bytes, size_t len) {
    if (bytes == nullptr) return "<null>";

    const uint8_t* bytes8 = static_cast<const uint8_t*>(bytes);
    char chars[] = "0123456789abcdef";
    std::string result;
    result.resize(len * 2);

    for (size_t i = 0; i < len; i++) {
        result[2 * i] = chars[bytes8[i] >> 4];
        result[2 * i + 1] = chars[bytes8[i] & 0xf];
    }

    return result;
}

class FooBar : public BBinder {
 public:
    enum {
        TRANSACTION_REPEAT_STRING = IBinder::FIRST_CALL_TRANSACTION,
    };

    std::mutex foo;
    std::string last;

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        // not checking data, since there is no hook at the time this test is
        // written to check values there are set to zero. Instead, we only check
        // the reply parcel.

        switch (code) {
            case TRANSACTION_REPEAT_STRING: {
                const char* str = data.readCString();
                return reply->writeCString(str == nullptr ? "<null>" : str);
            }
        }
        return BBinder::onTransact(code, data, reply, flags);
    }
    static std::string RepeatString(const sp<IBinder> binder,
                                    const std::string& repeat,
                                    std::string* outBuffer) {
        Parcel data;
        data.writeCString(repeat.c_str());
        std::string result;
        const uint8_t* lastReply;
        size_t lastReplySize;
        {
            Parcel reply;
            binder->transact(TRANSACTION_REPEAT_STRING, data, &reply, FLAG_CLEAR_BUF);
            result = reply.readCString();
            lastReply = reply.data();
            lastReplySize = reply.dataSize();
        }
        *outBuffer = hexString(lastReply, lastReplySize);
        return result;
    }
};

TEST(BinderClearBuf, ClearKernelBuffer) {
    sp<IBinder> binder = defaultServiceManager()->getService(kServerName);
    ASSERT_NE(nullptr, binder);

    std::string replyBuffer;
    std::string result = FooBar::RepeatString(binder, "foo", &replyBuffer);
    EXPECT_EQ("foo", result);

    // the buffer must have at least some length for the string, but we will
    // just check it has some length, to avoid assuming anything about the
    // format
    EXPECT_GT(replyBuffer.size(), 0);

    for (size_t i = 0; i < replyBuffer.size(); i++) {
        EXPECT_EQ(replyBuffer[i], '0') << "reply buffer at " << i;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        sp<IBinder> server = new FooBar;
        android::defaultServiceManager()->addService(kServerName, server);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }

    // This is not racey. Just giving these services some time to register before we call
    // getService which sleeps for much longer. One alternative would be to
    // start a threadpool + use waitForService, but we want to have as few
    // binder things going on in this test as possible, since we are checking
    // memory is zero'd which the kernel has a right to change.
    usleep(100000);

    return RUN_ALL_TESTS();
}
