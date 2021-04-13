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

#include <PersistableBundleFuzzFunctions.h>
#include <binder/PersistableBundle.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/String16.h>

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<os::PersistableBundle> p_bundle(new os::PersistableBundle());

    while (fdp.remaining_bytes() > 0) {
        String16 key(fdp.ConsumeRandomLengthString(fdp.remaining_bytes()).c_str());
        callArbitraryFunction(&fdp, gPersistableBundleOperations, p_bundle, &key);
    }

    return 0;
}

} // namespace android
