/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include "AIBinder_internal.h"

#include <binder/IServiceManager.h>

using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::IServiceManager;
using ::android::sp;
using ::android::String16;

binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return EX_NULL_POINTER;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    return sm->addService(String16(instance), binder->getBinder());
}
AIBinder* AServiceManager_getService(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(instance));

    AIBinder* ret = new ABpBinder(binder);
    AIBinder_incStrong(ret);
    return ret;
}
