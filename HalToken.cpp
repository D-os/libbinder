/*
 * Copyright (C) 2005 The Android Open Source Project
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

#define LOG_TAG "HalToken"

#include <utils/Log.h>
#include <binder/HalToken.h>

#include <android/hidl/token/1.0/ITokenManager.h>

namespace android {

using ::android::hidl::token::V1_0::ITokenManager;

sp<ITokenManager> gTokenManager = nullptr;

ITokenManager* getTokenManager() {
    if (gTokenManager != nullptr) {
        return gTokenManager.get();
    }
    gTokenManager = ITokenManager::getService();
    if (gTokenManager == nullptr) {
        ALOGE("Cannot retrieve TokenManager.");
    }
    return gTokenManager.get();
}

sp<HInterface> retrieveHalInterface(const HalToken& token) {
    auto transaction = getTokenManager()->get(token);
    if (!transaction.isOk()) {
        ALOGE("getHalInterface: Cannot obtain interface from token.");
        return nullptr;
    }
    return static_cast<sp<HInterface> >(transaction);
}

bool createHalToken(const sp<HInterface>& interface, HalToken* token) {
    auto transaction = getTokenManager()->createToken(interface);
    if (!transaction.isOk()) {
        ALOGE("createHalToken: Cannot create token from interface.");
        return false;
    }
    *token = static_cast<HalToken>(transaction);
    return true;
}

bool deleteHalToken(const HalToken& token) {
    auto transaction = getTokenManager()->unregister(token);
    if (!transaction.isOk()) {
        ALOGE("deleteHalToken: Cannot unregister hal token.");
        return false;
    }
    return true;
}

}; // namespace android

