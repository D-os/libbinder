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

#include <BpBinderFuzzFunctions.h>
#include <IBinderFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // TODO: In the future it would be more effective to fork a new process and then pass a BBinder
    // to your process. Right now this is not implemented because it would involved fuzzing IPC on a
    // forked process, and libfuzzer will not be able to handle code coverage. This would lead to
    // crashes that are not easy to diagnose.
    int32_t handle = fdp.ConsumeIntegralInRange<int32_t>(0, 1024);
    sp<BpBinder> bpbinder = BpBinder::create(handle);
    if (bpbinder == nullptr) return 0;

    // To prevent memory from running out from calling too many add item operations.
    const uint32_t MAX_RUNS = 2048;
    uint32_t count = 0;
    sp<IBinder::DeathRecipient> s_recipient = new FuzzDeathRecipient();

    while (fdp.remaining_bytes() > 0 && count++ < MAX_RUNS) {
        if (fdp.ConsumeBool()) {
            callArbitraryFunction(&fdp, gBPBinderOperations, bpbinder, s_recipient);
        } else {
            callArbitraryFunction(&fdp, gIBinderOperations, bpbinder.get());
        }
    }

    return 0;
}
} // namespace android
