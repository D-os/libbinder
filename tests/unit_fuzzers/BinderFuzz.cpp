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

#include <BinderFuzzFunctions.h>
#include <IBinderFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/Binder.h>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    sp<BBinder> bbinder = new BBinder();

    // To prevent memory from running out from calling too many add item operations.
    const uint32_t MAX_RUNS = 2048;
    uint32_t count = 0;

    while (fdp.remaining_bytes() > 0 && count++ < MAX_RUNS) {
        if (fdp.ConsumeBool()) {
            callArbitraryFunction(&fdp, gBBinderOperations, bbinder);
        } else {
            callArbitraryFunction(&fdp, gIBinderOperations,
                                  reinterpret_cast<IBinder *>(bbinder.get()));
        }
    }

    return 0;
}
} // namespace android
