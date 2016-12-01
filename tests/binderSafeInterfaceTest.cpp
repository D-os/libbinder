/*
 * Copyright 2016 The Android Open Source Project
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

#include <binder/SafeInterface.h>

#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <binder/ProcessState.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <gtest/gtest.h>
#pragma clang diagnostic pop

#include <optional>

using namespace std::chrono_literals; // NOLINT - google-build-using-namespace

namespace android {
namespace tests {

// This class serves two purposes:
//   1) It ensures that the implementation doesn't require copying or moving the data (for
//      efficiency purposes)
//   2) It tests that Parcelables can be passed correctly
class NoCopyNoMove : public Parcelable {
public:
    NoCopyNoMove() = default;
    explicit NoCopyNoMove(int32_t value) : mValue(value) {}
    ~NoCopyNoMove() override = default;

    // Not copyable
    NoCopyNoMove(const NoCopyNoMove&) = delete;
    NoCopyNoMove& operator=(const NoCopyNoMove&) = delete;

    // Not movable
    NoCopyNoMove(NoCopyNoMove&&) = delete;
    NoCopyNoMove& operator=(NoCopyNoMove&&) = delete;

    // Parcelable interface
    status_t writeToParcel(Parcel* parcel) const override { return parcel->writeInt32(mValue); }
    status_t readFromParcel(const Parcel* parcel) override { return parcel->readInt32(&mValue); }

    int32_t getValue() const { return mValue; }
    void setValue(int32_t value) { mValue = value; }

private:
    int32_t mValue = 0;
    uint8_t mPadding[4] = {}; // Avoids a warning from -Wpadded
};

struct TestLightFlattenable : LightFlattenablePod<TestLightFlattenable> {
    TestLightFlattenable() = default;
    explicit TestLightFlattenable(int32_t v) : value(v) {}
    int32_t value = 0;
};

class ExitOnDeath : public IBinder::DeathRecipient {
public:
    ~ExitOnDeath() override = default;

    void binderDied(const wp<IBinder>& /*who*/) override {
        ALOG(LOG_INFO, "ExitOnDeath", "Exiting");
        exit(0);
    }
};

// This callback class is used to test both one-way transactions and that sp<IInterface> can be
// passed correctly
class ICallback : public IInterface {
public:
    DECLARE_META_INTERFACE(Callback)

    enum class Tag : uint32_t {
        OnCallback = IBinder::FIRST_CALL_TRANSACTION,
        Last,
    };

    virtual void onCallback(int32_t aPlusOne) = 0;
};

class BpCallback : public SafeBpInterface<ICallback> {
public:
    explicit BpCallback(const sp<IBinder>& impl) : SafeBpInterface<ICallback>(impl, getLogTag()) {}

    void onCallback(int32_t aPlusOne) override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemoteAsync<decltype(&ICallback::onCallback)>(Tag::OnCallback, aPlusOne);
    }

private:
    static constexpr const char* getLogTag() { return "BpCallback"; }
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexit-time-destructors"
IMPLEMENT_META_INTERFACE(Callback, "android.gfx.tests.ICallback");
#pragma clang diagnostic pop

class BnCallback : public SafeBnInterface<ICallback> {
public:
    BnCallback() : SafeBnInterface("BnCallback") {}

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                        uint32_t /*flags*/) override {
        EXPECT_GE(code, IBinder::FIRST_CALL_TRANSACTION);
        EXPECT_LT(code, static_cast<uint32_t>(ICallback::Tag::Last));
        ICallback::Tag tag = static_cast<ICallback::Tag>(code);
        switch (tag) {
            case ICallback::Tag::OnCallback: {
                return callLocalAsync(data, reply, &ICallback::onCallback);
            }
            case ICallback::Tag::Last:
                // Should not be possible because of the asserts at the beginning of the method
                [&]() { FAIL(); }();
                return UNKNOWN_ERROR;
        }
    }
};

class ISafeInterfaceTest : public IInterface {
public:
    DECLARE_META_INTERFACE(SafeInterfaceTest)

    enum class Tag : uint32_t {
        SetDeathToken = IBinder::FIRST_CALL_TRANSACTION,
        ReturnsNoMemory,
        LogicalNot,
        IncrementLightFlattenable,
        IncrementNoCopyNoMove,
        ToUpper,
        CallMeBack,
        IncrementInt32,
        IncrementUint32,
        IncrementTwo,
        Last,
    };

    // This is primarily so that the remote service dies when the test does, but it also serves to
    // test the handling of sp<IBinder> and non-const methods
    virtual status_t setDeathToken(const sp<IBinder>& token) = 0;

    // This is the most basic test since it doesn't require parceling any arguments
    virtual status_t returnsNoMemory() const = 0;

    // These are ordered according to their corresponding methods in SafeInterface::ParcelHandler
    virtual status_t logicalNot(bool a, bool* notA) const = 0;
    virtual status_t increment(const TestLightFlattenable& a,
                               TestLightFlattenable* aPlusOne) const = 0;
    virtual status_t increment(const NoCopyNoMove& a, NoCopyNoMove* aPlusOne) const = 0;
    virtual status_t toUpper(const String8& str, String8* upperStr) const = 0;
    // As mentioned above, sp<IBinder> is already tested by setDeathToken
    virtual void callMeBack(const sp<ICallback>& callback, int32_t a) const = 0;
    virtual status_t increment(int32_t a, int32_t* aPlusOne) const = 0;
    virtual status_t increment(uint32_t a, uint32_t* aPlusOne) const = 0;

    // This tests that input/output parameter interleaving works correctly
    virtual status_t increment(int32_t a, int32_t* aPlusOne, int32_t b,
                               int32_t* bPlusOne) const = 0;
};

class BpSafeInterfaceTest : public SafeBpInterface<ISafeInterfaceTest> {
public:
    explicit BpSafeInterfaceTest(const sp<IBinder>& impl)
          : SafeBpInterface<ISafeInterfaceTest>(impl, getLogTag()) {}

    status_t setDeathToken(const sp<IBinder>& token) override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemote<decltype(&ISafeInterfaceTest::setDeathToken)>(Tag::SetDeathToken, token);
    }
    status_t returnsNoMemory() const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemote<decltype(&ISafeInterfaceTest::returnsNoMemory)>(Tag::ReturnsNoMemory);
    }
    status_t logicalNot(bool a, bool* notA) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemote<decltype(&ISafeInterfaceTest::logicalNot)>(Tag::LogicalNot, a, notA);
    }
    status_t increment(const TestLightFlattenable& a,
                       TestLightFlattenable* aPlusOne) const override {
        using Signature = status_t (ISafeInterfaceTest::*)(const TestLightFlattenable&,
                                                           TestLightFlattenable*) const;
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemote<Signature>(Tag::IncrementLightFlattenable, a, aPlusOne);
    }
    status_t increment(const NoCopyNoMove& a, NoCopyNoMove* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        using Signature = status_t (ISafeInterfaceTest::*)(const NoCopyNoMove& a,
                                                           NoCopyNoMove* aPlusOne) const;
        return callRemote<Signature>(Tag::IncrementNoCopyNoMove, a, aPlusOne);
    }
    status_t toUpper(const String8& str, String8* upperStr) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemote<decltype(&ISafeInterfaceTest::toUpper)>(Tag::ToUpper, str, upperStr);
    }
    void callMeBack(const sp<ICallback>& callback, int32_t a) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return callRemoteAsync<decltype(&ISafeInterfaceTest::callMeBack)>(Tag::CallMeBack, callback,
                                                                          a);
    }
    status_t increment(int32_t a, int32_t* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        using Signature = status_t (ISafeInterfaceTest::*)(int32_t, int32_t*) const;
        return callRemote<Signature>(Tag::IncrementInt32, a, aPlusOne);
    }
    status_t increment(uint32_t a, uint32_t* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        using Signature = status_t (ISafeInterfaceTest::*)(uint32_t, uint32_t*) const;
        return callRemote<Signature>(Tag::IncrementUint32, a, aPlusOne);
    }
    status_t increment(int32_t a, int32_t* aPlusOne, int32_t b, int32_t* bPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        using Signature =
                status_t (ISafeInterfaceTest::*)(int32_t, int32_t*, int32_t, int32_t*) const;
        return callRemote<Signature>(Tag::IncrementTwo, a, aPlusOne, b, bPlusOne);
    }

private:
    static constexpr const char* getLogTag() { return "BpSafeInterfaceTest"; }
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexit-time-destructors"
IMPLEMENT_META_INTERFACE(SafeInterfaceTest, "android.gfx.tests.ISafeInterfaceTest");

static sp<IBinder::DeathRecipient> getDeathRecipient() {
    static sp<IBinder::DeathRecipient> recipient = new ExitOnDeath;
    return recipient;
}
#pragma clang diagnostic pop

class BnSafeInterfaceTest : public SafeBnInterface<ISafeInterfaceTest> {
public:
    BnSafeInterfaceTest() : SafeBnInterface(getLogTag()) {}

    status_t setDeathToken(const sp<IBinder>& token) override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        token->linkToDeath(getDeathRecipient());
        return NO_ERROR;
    }
    status_t returnsNoMemory() const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        return NO_MEMORY;
    }
    status_t logicalNot(bool a, bool* notA) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        *notA = !a;
        return NO_ERROR;
    }
    status_t increment(const TestLightFlattenable& a,
                       TestLightFlattenable* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        aPlusOne->value = a.value + 1;
        return NO_ERROR;
    }
    status_t increment(const NoCopyNoMove& a, NoCopyNoMove* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        aPlusOne->setValue(a.getValue() + 1);
        return NO_ERROR;
    }
    status_t toUpper(const String8& str, String8* upperStr) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        *upperStr = str;
        upperStr->toUpper();
        return NO_ERROR;
    }
    void callMeBack(const sp<ICallback>& callback, int32_t a) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        callback->onCallback(a + 1);
    }
    status_t increment(int32_t a, int32_t* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        *aPlusOne = a + 1;
        return NO_ERROR;
    }
    status_t increment(uint32_t a, uint32_t* aPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        *aPlusOne = a + 1;
        return NO_ERROR;
    }
    status_t increment(int32_t a, int32_t* aPlusOne, int32_t b, int32_t* bPlusOne) const override {
        ALOG(LOG_INFO, getLogTag(), "%s", __PRETTY_FUNCTION__);
        *aPlusOne = a + 1;
        *bPlusOne = b + 1;
        return NO_ERROR;
    }

    // BnInterface
    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                        uint32_t /*flags*/) override {
        EXPECT_GE(code, IBinder::FIRST_CALL_TRANSACTION);
        EXPECT_LT(code, static_cast<uint32_t>(Tag::Last));
        ISafeInterfaceTest::Tag tag = static_cast<ISafeInterfaceTest::Tag>(code);
        switch (tag) {
            case ISafeInterfaceTest::Tag::SetDeathToken: {
                return callLocal(data, reply, &ISafeInterfaceTest::setDeathToken);
            }
            case ISafeInterfaceTest::Tag::ReturnsNoMemory: {
                return callLocal(data, reply, &ISafeInterfaceTest::returnsNoMemory);
            }
            case ISafeInterfaceTest::Tag::LogicalNot: {
                return callLocal(data, reply, &ISafeInterfaceTest::logicalNot);
            }
            case ISafeInterfaceTest::Tag::IncrementLightFlattenable: {
                using Signature =
                        status_t (ISafeInterfaceTest::*)(const TestLightFlattenable& a,
                                                         TestLightFlattenable* aPlusOne) const;
                return callLocal<Signature>(data, reply, &ISafeInterfaceTest::increment);
            }
            case ISafeInterfaceTest::Tag::IncrementNoCopyNoMove: {
                using Signature = status_t (ISafeInterfaceTest::*)(const NoCopyNoMove& a,
                                                                   NoCopyNoMove* aPlusOne) const;
                return callLocal<Signature>(data, reply, &ISafeInterfaceTest::increment);
            }
            case ISafeInterfaceTest::Tag::ToUpper: {
                return callLocal(data, reply, &ISafeInterfaceTest::toUpper);
            }
            case ISafeInterfaceTest::Tag::CallMeBack: {
                return callLocalAsync(data, reply, &ISafeInterfaceTest::callMeBack);
            }
            case ISafeInterfaceTest::Tag::IncrementInt32: {
                using Signature = status_t (ISafeInterfaceTest::*)(int32_t, int32_t*) const;
                return callLocal<Signature>(data, reply, &ISafeInterfaceTest::increment);
            }
            case ISafeInterfaceTest::Tag::IncrementUint32: {
                using Signature = status_t (ISafeInterfaceTest::*)(uint32_t, uint32_t*) const;
                return callLocal<Signature>(data, reply, &ISafeInterfaceTest::increment);
            }
            case ISafeInterfaceTest::Tag::IncrementTwo: {
                using Signature = status_t (ISafeInterfaceTest::*)(int32_t, int32_t*, int32_t,
                                                                   int32_t*) const;
                return callLocal<Signature>(data, reply, &ISafeInterfaceTest::increment);
            }
            case ISafeInterfaceTest::Tag::Last:
                // Should not be possible because of the asserts at the beginning of the method
                [&]() { FAIL(); }();
                return UNKNOWN_ERROR;
        }
    }

private:
    static constexpr const char* getLogTag() { return "BnSafeInterfaceTest"; }
};

class SafeInterfaceTest : public ::testing::Test {
public:
    SafeInterfaceTest() : mSafeInterfaceTest(getRemoteService()) {
        ProcessState::self()->startThreadPool();
    }
    ~SafeInterfaceTest() override = default;

protected:
    sp<ISafeInterfaceTest> mSafeInterfaceTest;

private:
    static constexpr const char* getLogTag() { return "SafeInterfaceTest"; }

    sp<ISafeInterfaceTest> getRemoteService() {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexit-time-destructors"
        static std::mutex sMutex;
        static sp<ISafeInterfaceTest> sService;
        static sp<IBinder> sDeathToken = new BBinder;
#pragma clang diagnostic pop

        std::unique_lock<decltype(sMutex)> lock;
        if (sService == nullptr) {
            ALOG(LOG_INFO, getLogTag(), "Forking remote process");
            pid_t forkPid = fork();
            EXPECT_NE(forkPid, -1);

            const String16 serviceName("SafeInterfaceTest");

            if (forkPid == 0) {
                ALOG(LOG_INFO, getLogTag(), "Remote process checking in");
                sp<ISafeInterfaceTest> nativeService = new BnSafeInterfaceTest;
                defaultServiceManager()->addService(serviceName,
                                                    IInterface::asBinder(nativeService));
                ProcessState::self()->startThreadPool();
                IPCThreadState::self()->joinThreadPool();
                // We shouldn't get to this point
                [&]() { FAIL(); }();
            }

            sp<IBinder> binder = defaultServiceManager()->getService(serviceName);
            sService = interface_cast<ISafeInterfaceTest>(binder);
            EXPECT_TRUE(sService != nullptr);

            sService->setDeathToken(sDeathToken);
        }

        return sService;
    }
};

TEST_F(SafeInterfaceTest, TestReturnsNoMemory) {
    status_t result = mSafeInterfaceTest->returnsNoMemory();
    ASSERT_EQ(NO_MEMORY, result);
}

TEST_F(SafeInterfaceTest, TestLogicalNot) {
    const bool a = true;
    bool notA = true;
    status_t result = mSafeInterfaceTest->logicalNot(a, &notA);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(!a, notA);
    // Test both since we don't want to accidentally catch a default false somewhere
    const bool b = false;
    bool notB = false;
    result = mSafeInterfaceTest->logicalNot(b, &notB);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(!b, notB);
}

TEST_F(SafeInterfaceTest, TestIncrementLightFlattenable) {
    const TestLightFlattenable a{1};
    TestLightFlattenable aPlusOne{0};
    status_t result = mSafeInterfaceTest->increment(a, &aPlusOne);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(a.value + 1, aPlusOne.value);
}

TEST_F(SafeInterfaceTest, TestIncrementNoCopyNoMove) {
    const NoCopyNoMove a{1};
    NoCopyNoMove aPlusOne{0};
    status_t result = mSafeInterfaceTest->increment(a, &aPlusOne);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(a.getValue() + 1, aPlusOne.getValue());
}

TEST_F(SafeInterfaceTest, TestToUpper) {
    const String8 str{"Hello, world!"};
    String8 upperStr;
    status_t result = mSafeInterfaceTest->toUpper(str, &upperStr);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_TRUE(upperStr == String8{"HELLO, WORLD!"});
}

TEST_F(SafeInterfaceTest, TestCallMeBack) {
    class CallbackReceiver : public BnCallback {
    public:
        void onCallback(int32_t aPlusOne) override {
            ALOG(LOG_INFO, "CallbackReceiver", "%s", __PRETTY_FUNCTION__);
            std::unique_lock<decltype(mMutex)> lock(mMutex);
            mValue = aPlusOne;
            mCondition.notify_one();
        }

        std::optional<int32_t> waitForCallback() {
            std::unique_lock<decltype(mMutex)> lock(mMutex);
            bool success =
                    mCondition.wait_for(lock, 100ms, [&]() { return static_cast<bool>(mValue); });
            return success ? mValue : std::nullopt;
        }

    private:
        std::mutex mMutex;
        std::condition_variable mCondition;
        std::optional<int32_t> mValue;
    };

    sp<CallbackReceiver> receiver = new CallbackReceiver;
    const int32_t a = 1;
    mSafeInterfaceTest->callMeBack(receiver, a);
    auto result = receiver->waitForCallback();
    ASSERT_TRUE(result);
    ASSERT_EQ(a + 1, *result);
}

TEST_F(SafeInterfaceTest, TestIncrementInt32) {
    const int32_t a = 1;
    int32_t aPlusOne = 0;
    status_t result = mSafeInterfaceTest->increment(a, &aPlusOne);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(a + 1, aPlusOne);
}

TEST_F(SafeInterfaceTest, TestIncrementUint32) {
    const uint32_t a = 1;
    uint32_t aPlusOne = 0;
    status_t result = mSafeInterfaceTest->increment(a, &aPlusOne);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(a + 1, aPlusOne);
}

TEST_F(SafeInterfaceTest, TestIncrementTwo) {
    const int32_t a = 1;
    int32_t aPlusOne = 0;
    const int32_t b = 2;
    int32_t bPlusOne = 0;
    status_t result = mSafeInterfaceTest->increment(1, &aPlusOne, 2, &bPlusOne);
    ASSERT_EQ(NO_ERROR, result);
    ASSERT_EQ(a + 1, aPlusOne);
    ASSERT_EQ(b + 1, bPlusOne);
}

} // namespace tests
} // namespace android
