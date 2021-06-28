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

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <gtest/gtest.h>

using android::BBinder;
using android::OK;
using android::sp;

const void* kObjectId1 = reinterpret_cast<const void*>(1);
const void* kObjectId2 = reinterpret_cast<const void*>(2);
void* kObject1 = reinterpret_cast<void*>(101);
void* kObject2 = reinterpret_cast<void*>(102);
void* kObject3 = reinterpret_cast<void*>(103);

TEST(Binder, AttachObject) {
    auto binder = sp<BBinder>::make();
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject1, nullptr, nullptr));
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId2, kObject2, nullptr, nullptr));
    EXPECT_EQ(kObject1, binder->attachObject(kObjectId1, kObject3, nullptr, nullptr));
}

TEST(Binder, DetachObject) {
    auto binder = sp<BBinder>::make();
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject1, nullptr, nullptr));
    EXPECT_EQ(kObject1, binder->detachObject(kObjectId1));
    EXPECT_EQ(nullptr, binder->attachObject(kObjectId1, kObject2, nullptr, nullptr));
}
