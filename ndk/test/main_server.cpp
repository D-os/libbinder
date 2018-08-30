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

#include <android-base/logging.h>
#include <android/binder_process.h>
#include <iface/iface.h>

using ::android::sp;

class MyFoo : public IFoo {
    int32_t doubleNumber(int32_t in) override {
        LOG(INFO) << "doubling " << in;
        return 2 * in;
    }
};

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    // Strong reference to MyFoo kept by service manager.
    binder_status_t status = (new MyFoo)->addService(IFoo::kSomeInstanceName);

    if (status != EX_NONE) {
        LOG(FATAL) << "Could not register: " << status;
    }

    ABinderProcess_joinThreadPool();

    return 1;
}
