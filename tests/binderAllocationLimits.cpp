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
#include <binder/Parcel.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <utils/CallStack.h>

#include <malloc.h>
#include <functional>
#include <vector>

struct DestructionAction {
    DestructionAction(std::function<void()> f) : mF(std::move(f)) {}
    ~DestructionAction() { mF(); };
private:
    std::function<void()> mF;
};

// Group of hooks
struct MallocHooks {
    decltype(__malloc_hook) malloc_hook;
    decltype(__realloc_hook) realloc_hook;

    static MallocHooks save() {
        return {
            .malloc_hook = __malloc_hook,
            .realloc_hook = __realloc_hook,
        };
    }

    void overwrite() const {
        __malloc_hook = malloc_hook;
        __realloc_hook = realloc_hook;
    }
};

static const MallocHooks orig_malloc_hooks = MallocHooks::save();

// When malloc is hit, executes lambda.
namespace LambdaHooks {
    using AllocationHook = std::function<void(size_t)>;
    static std::vector<AllocationHook> lambdas = {};

    static void* lambda_realloc_hook(void* ptr, size_t bytes, const void* arg);
    static void* lambda_malloc_hook(size_t bytes, const void* arg);

    static const MallocHooks lambda_malloc_hooks = {
        .malloc_hook = lambda_malloc_hook,
        .realloc_hook = lambda_realloc_hook,
    };

    static void* lambda_malloc_hook(size_t bytes, const void* arg) {
        {
            orig_malloc_hooks.overwrite();
            lambdas.at(lambdas.size() - 1)(bytes);
            lambda_malloc_hooks.overwrite();
        }
        return orig_malloc_hooks.malloc_hook(bytes, arg);
    }

    static void* lambda_realloc_hook(void* ptr, size_t bytes, const void* arg) {
        {
            orig_malloc_hooks.overwrite();
            lambdas.at(lambdas.size() - 1)(bytes);
            lambda_malloc_hooks.overwrite();
        }
        return orig_malloc_hooks.realloc_hook(ptr, bytes, arg);
    }

}

// Action to execute when malloc is hit. Supports nesting. Malloc is not
// restricted when the allocation hook is being processed.
__attribute__((warn_unused_result))
DestructionAction OnMalloc(LambdaHooks::AllocationHook f) {
    MallocHooks before = MallocHooks::save();
    LambdaHooks::lambdas.emplace_back(std::move(f));
    LambdaHooks::lambda_malloc_hooks.overwrite();
    return DestructionAction([before]() {
        before.overwrite();
        LambdaHooks::lambdas.pop_back();
    });
}

// exported symbol, to force compiler not to optimize away pointers we set here
const void* imaginary_use;

TEST(TestTheTest, OnMalloc) {
    size_t mallocs = 0;
    {
        const auto on_malloc = OnMalloc([&](size_t bytes) {
            mallocs++;
            EXPECT_EQ(bytes, 40);
        });

        imaginary_use = new int[10];
    }
    EXPECT_EQ(mallocs, 1);
}


__attribute__((warn_unused_result))
DestructionAction ScopeDisallowMalloc() {
    return OnMalloc([&](size_t bytes) {
        ADD_FAILURE() << "Unexpected allocation: " << bytes;
        using android::CallStack;
        std::cout << CallStack::stackToString("UNEXPECTED ALLOCATION", CallStack::getCurrent(4 /*ignoreDepth*/).get())
                  << std::endl;
    });
}

using android::IBinder;
using android::Parcel;
using android::String16;
using android::defaultServiceManager;
using android::sp;
using android::IServiceManager;

static sp<IBinder> GetRemoteBinder() {
    // This gets binder representing the service manager
    // the current IServiceManager API doesn't expose the binder, and
    // I want to avoid adding usages of the AIDL generated interface it
    // is using underneath, so to avoid people copying it.
    sp<IBinder> binder = defaultServiceManager()->checkService(String16("manager"));
    EXPECT_NE(nullptr, binder);
    return binder;
}

TEST(BinderAllocation, ParcelOnStack) {
    const auto m = ScopeDisallowMalloc();
    Parcel p;
    imaginary_use = p.data();
}

TEST(BinderAllocation, GetServiceManager) {
    defaultServiceManager(); // first call may alloc
    const auto m = ScopeDisallowMalloc();
    defaultServiceManager();
}

// note, ping does not include interface descriptor
TEST(BinderAllocation, PingTransaction) {
    sp<IBinder> a_binder = GetRemoteBinder();
    const auto m = ScopeDisallowMalloc();
    a_binder->pingBinder();
}

TEST(BinderAllocation, SmallTransaction) {
    String16 empty_descriptor = String16("");
    sp<IServiceManager> manager = defaultServiceManager();

    size_t mallocs = 0;
    const auto on_malloc = OnMalloc([&](size_t bytes) {
        mallocs++;
        // Parcel should allocate a small amount by default
        EXPECT_EQ(bytes, 128);
    });
    manager->checkService(empty_descriptor);

    EXPECT_EQ(mallocs, 1);
}

int main(int argc, char** argv) {
    if (getenv("LIBC_HOOKS_ENABLE") == nullptr) {
        CHECK(0 == setenv("LIBC_HOOKS_ENABLE", "1", true /*overwrite*/));
        execv(argv[0], argv);
        return 1;
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
